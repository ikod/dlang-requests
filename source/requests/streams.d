module requests.streams;

private:
import std.algorithm;
import std.array;
import std.conv;
import std.experimental.logger;
import std.exception;
import std.format;
import std.range;
import std.range.primitives;
import std.string;
import std.stdio;
import std.traits;
import std.zlib;
import std.datetime;
import std.socket;

public class ConnectError: Exception {
    this(string msg, string file = __FILE__, size_t line = __LINE__) @safe pure {
        super(msg, file, line);
    }
}

class DecodingExceptioin: Exception {
    this(string msg, string file = __FILE__, size_t line = __LINE__) @safe pure {
        super(msg, file, line);
    }
}
/**
 * DataPipeIface can accept some data, process, and return processed data.
 */
public interface DataPipeIface(E) {
    /// Is there any processed data ready for reading?
    bool empty();
    /// Put next data portion for processing
    void put(E[]);
    /// Get any ready data
    E[] get();
    /// Signal on end of incoming data stream.
    void flush();
}
/**
 * DataPipe is a pipeline of data processors, each accept some data, process it, and put result to next element in line.
 * This class used to combine different Transfer- and Content- encodings. For example: unchunk chunked transfer-encoding,
 * and uncompress compressed Content-Encoding.
 */
public class DataPipe(E) : DataPipeIface!E {

    DataPipeIface!(E)[]  pipe;
    Buffer!E             buffer;
    /// Append data processor to pipeline
    /// Params:
    /// p = processor
    void insert(DataPipeIface!E p) {
        pipe ~= p;
    }
    E[][] process(DataPipeIface!E p, E[][] data) {
        E[][] result;
        data.each!(e => p.put(e));
        while(!p.empty()) result ~= p.get();
        return result;
    }
    /// Process next data portion. Data passed over pipeline and result stored in buffer.
    /// Params:
    /// data = input data array.
    void put(E[] data) {
        if ( pipe.empty ) {
            buffer.put(data);
            return;
        }
        auto t = process(pipe.front, [data]);
        foreach(ref p; pipe[1..$]) {
            t = process(p, t);
        }
        t.each!(b => buffer.put(b));
    }
    /// Process next data portion. Data passed over pipeline and store result in buffer.
    /// Params:
    /// buff = input data buffer.
    void put(Buffer!E buff) {
        if ( pipe.empty ) {
            if ( buffer.__repr is null ) {
                buffer = buff;
                return;
            }
            buffer.__repr.__buffer ~= buff.__repr.__buffer;
            buffer.__repr.__length += buff.length;
            return;
        }
        auto t = process(pipe.front, buff.__repr.__buffer);
        foreach(ref p; pipe[1..$]) {
            t = process(p, t);
        }
        t.each!(b => buffer.put(b));
    }
    /// Get what was collected in internal buffer and clear it. 
    /// Returns:
    /// data collected.
    E[] get() pure {
        if ( buffer.empty ) {
            return E[].init;
        }
        auto res = buffer.data;
        buffer = Buffer!E.init;
        return res;
    }
    /// Test if internal buffer is empty
    /// Returns:
    /// true if internal buffer is empty (nothing to get())
    bool empty() pure const @safe {
        return buffer.empty;
    }
    void flush() {
        E[][] product;
        foreach(ref p; pipe) {
            product.each!(e => p.put(e));
            p.flush();
            product.length = 0;
            while( !p.empty ) product ~= p.get();
        }
        product.each!(b => buffer.put(b));
    }
}

/**
 * Processor for gzipped/compressed content.
 * Also support InputRange interface.
 */
public class Decompressor(E) : DataPipeIface!E {
    private {
        Buffer!ubyte __buff;
        UnCompress   __zlib;
    }
    this() {
        __buff = Buffer!ubyte();
        __zlib = new UnCompress();
    }
//    this(E[] r) {
//        //__range = r;
//        __buff = Buffer!ubyte();
//        __zlib = new UnCompress();
//        auto l = r.length;
//        if ( l ) {
//            __buff.put(__zlib.uncompress(r.take(l)));
//        }
//    }
    override void put(E[] data) {
        if ( __zlib is null  ) {
            __zlib = new UnCompress();
        }
        __buff.put(__zlib.uncompress(data));
    }
    override E[] get() pure {
        assert(__buff.length);
        auto r = __buff.__repr.__buffer[0];
        __buff.popFrontN(r.length);
        return cast(E[])r;
    }
    override void flush() {
        if ( __zlib is null  ) {
            return;
        }
        __buff.put(__zlib.flush());
    }
    override @property bool empty() const pure @safe {
        debug tracef("empty=%b", __buff.empty);
        return __buff.empty;
    }
    @property auto ref front() pure const @safe {
        debug tracef("front: buff length=%d", __buff.length);
        return __buff.front;
    }
    @property auto popFront() pure @safe {
        debug tracef("popFront: buff length=%d", __buff.length);
        return __buff.popFront;
    }
    @property void popFrontN(size_t n) pure @safe {
        __buff.popFrontN(n);
    }
}

/**
 * Unchunk chunked http responce body.
 */
public class DecodeChunked : DataPipeIface!ubyte {
    //    length := 0
    //    read chunk-size, chunk-extension (if any) and CRLF
    //    while (chunk-size > 0) {
    //        read chunk-data and CRLF
    //        append chunk-data to entity-body
    //        length := length + chunk-size
    //        read chunk-size and CRLF
    //    }
    //    read entity-header
    //    while (entity-header not empty) {
    //        append entity-header to existing header fields
    //        read entity-header
    //    }
    //    Content-Length := length
    //    Remove "chunked" from Transfer-Encoding
    //

    //    Chunked-Body   = *chunk
    //                      last-chunk
    //                      trailer
    //                      CRLF
    //            
    //    chunk          = chunk-size [ chunk-extension ] CRLF
    //                     chunk-data CRLF
    //                     chunk-size     = 1*HEX
    //                     last-chunk     = 1*("0") [ chunk-extension ] CRLF
    //        
    //    chunk-extension= *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
    //    chunk-ext-name = token
    //    chunk-ext-val  = token | quoted-string
    //    chunk-data     = chunk-size(OCTET)
    //    trailer        = *(entity-header CRLF)

    alias eType = ubyte;
    immutable eType[] CRLF = ['\r', '\n'];
    private {
        enum         States {huntingSize, huntingSeparator, receiving, trailer};
        char         state = States.huntingSize;
        size_t       chunk_size, to_receive;
        Buffer!ubyte buff;
        ubyte[]      linebuff;
    }
    void put(eType[] data) {
        while ( data.length ) {
            if ( state == States.trailer ) {
                return;
            }
            if ( state == States.huntingSize ) {
                linebuff ~= data;
                data.length = 0;
                auto s = linebuff.findSplit(CRLF);
                if ( !s[1].length ) {
                    if ( linebuff.length >= 80 ) {
                        throw new DecodingExceptioin("Can't find chunk size in the body");
                    }
                    continue;
                }
                string x = castFrom!(ubyte[]).to!string(s[0]);
                formattedRead(x, "%x", &chunk_size);
                tracef("Got chunk size %s", chunk_size);
                state = States.receiving;
                to_receive = chunk_size;
                data = s[2];
                if ( chunk_size == 0 ) {
                    state = States.trailer;
                    tracef("Unchunk completed");
                    return;
                }
                continue;
            }
            if ( state == States.receiving ) {
                if (to_receive > 0 ) {
                    auto can_store = min(to_receive, data.length);
                    buff.put(data[0..can_store]);
                    data = data[can_store..$];
                    to_receive -= can_store;
                    tracef("Unchunked %d bytes from %d", can_store, chunk_size);
                    if ( to_receive == 0 ) {
                        tracef("switch to huntig separator");
                        state = States.huntingSeparator;
                        to_receive = 2;
                        linebuff.length = 0;
                        continue;
                    }
                    continue;
                }
                assert(false);
            }
            if ( state == States.huntingSeparator ) {
                linebuff ~= data;
                data.length = 0;
                auto s = linebuff.findSplit(CRLF);
                if ( s[1].length ) {
                    data = s[2];
                    chunk_size = 0;
                    linebuff.length = 0;
                    state = States.huntingSize;
                    tracef("switch to huntig size");
                    continue;
                }
            }
        }
    }
    eType[] get() {
        auto r = buff.__repr.__buffer[0];
        buff.popFrontN(r.length);
        return r;
    }
    void flush() {
    }
    bool empty() {
        debug tracef("empty=%b", buff.empty);
        return buff.empty;
    }
    bool done() {
        return state==States.trailer;
    }
}

unittest {
    info("Testing DataPipe");
    globalLogLevel(LogLevel.info);
    alias eType = char;
    eType[] gzipped = [
        0x1F, 0x8B, 0x08, 0x00, 0xB1, 0xA3, 0xEA, 0x56,
        0x00, 0x03, 0x4B, 0x4C, 0x4A, 0xE6, 0x4A, 0x49,
        0x4D, 0xE3, 0x02, 0x00, 0x75, 0x0B, 0xB0, 0x88,
        0x08, 0x00, 0x00, 0x00
    ]; // "abc\ndef\n"
    auto d = new Decompressor!eType();
    d.put(gzipped[0..2]);
    d.put(gzipped[2..10]);
    d.put(gzipped[10..$]);
    d.flush();
    assert(equal(d.filter!(a => a!='b'), "ac\ndef\n"));

    auto e = new Decompressor!eType();
    e.put(gzipped[0..10]);
    e.put(gzipped[10..$]);
    e.flush();
    assert(equal(e.filter!(a => a!='b'), "ac\ndef\n"));
    //    writeln(gzipped.decompress.filter!(a => a!='b').array);
    auto dp = new DataPipe!eType;
    dp.insert(new Decompressor!eType());
    dp.put(gzipped[0..2]);
    dp.put(gzipped[2..$]);
    dp.flush();
    assert(equal(dp.get(), "abc\ndef\n"));
    // empty datapipe shoul just pass input to output
    auto dpu = new DataPipe!ubyte;
    dpu.put("abcd".dup.representation);
    dpu.put("efgh".dup.representation);
    dpu.flush();
    assert(equal(dpu.get(), "abcdefgh"));
    info("Testing DataPipe - done");
}
/**
 * Buffer used to collect and process data from network. It remainds Appender, but support
 * also Range interface.
 * $(P To place data in buffer use put() method.)
 * $(P  To retrieve data from buffer you can use several methods:)
 * $(UL
 *  $(LI Range methods: front, back, index [])
 *  $(LI data method: return collected data (like Appender.data))
 * )
 */
public struct Buffer(T) {
    private {
        class Repr {
            size_t         __length;
            Unqual!T[][]   __buffer;
            this() {
                __length = 0;
            }
            this(Repr other) {
                if ( other is null )
                    return;
                __length = other.__length;
                __buffer = other.__buffer.dup;
            }
        }
        Repr __repr;
    }

    alias toString = data!string;

    this(this) {
        __repr = new Repr(__repr);
    }
    this(U)(U[] data) pure {
        put(data);
    }
   ~this() {
        __repr = null;
    }
    /***************
     * store data. Data copied
     */
    auto put(U)(U[] data) pure {
        if ( data.length == 0 ) {
            return this;
        }
        if ( !__repr ) {
            __repr = new Repr;
        }
        debug tracef("Append %d bytes", data.length);
        static if (!is(U == T)) {
            auto d = castFrom!(U[]).to!(T[])(data);
            __repr.__length += d.length;
            __repr.__buffer ~= d.dup;
        } else {
            __repr.__length += data.length;
            __repr.__buffer ~= data.dup;
        }
        return this;
    }
    @property auto opDollar() const pure @safe {
        return __repr.__length;
    }
    @property auto length() const pure @safe {
        if ( !__repr ) {
            return 0;
        }
        return __repr.__length;
    }
    @property auto empty() const pure @safe {
        return length == 0;
    }
    @property auto ref front() const pure @safe {
        assert(length);
        return __repr.__buffer.front.front;
    }
    @property auto ref back() const pure @safe {
        assert(length);
        return __repr.__buffer.back.back;
    }
    @property void popFront() pure @safe {
        assert(length);
        with ( __repr ) {
            __buffer.front.popFront;
            if ( __buffer.front.length == 0 ) {
                __buffer.popFront;
            }
            __length--;
        }
    }
    @property void popFrontN(size_t n) pure @safe {
        assert(n <= length, "lengnt: %d, n=%d".format(length, n));
        __repr.__length -= n;
        while( n ) {
            if ( n <= __repr.__buffer.front.length ) {
                __repr.__buffer.front.popFrontN(n);
                if ( __repr.__buffer.front.length == 0 ) {
                    __repr.__buffer.popFront;
                }
                return;
            }
            n -= __repr.__buffer.front.length;
            __repr.__buffer.popFront;
        }
    }
    @property void popBack() pure @safe {
        assert(length);
        __repr.__buffer.back.popBack;
        if ( __repr.__buffer.back.length == 0 ) {
            __repr.__buffer.popBack;
        }
        __repr.__length--;
    }
    @property void popBackN(size_t n) pure @safe {
        assert(n <= length);
        __repr.__length -= n;
        while( n ) {
            if ( n <= __repr.__buffer.back.length ) {
                __repr.__buffer.back.popBackN(n);
                if ( __repr.__buffer.back.length == 0 ) {
                    __repr.__buffer.popBack;
                }
                return;
            }
            n -= __repr.__buffer.back.length;
            __repr.__buffer.popBack;
        }
    }
    @property auto save() pure @safe {
        auto n = Buffer!T();
        n.__repr = new Repr(__repr);
        return n;
    }
    @property auto ref opIndex(size_t n) const pure @safe {
        assert( __repr && n < __repr.__length );
        foreach(b; __repr.__buffer) {
            if ( n < b.length ) {
                return b[n];
            }
            n -= b.length;
        }
        assert(false, "Impossible");
    }
    Buffer!T opSlice(size_t m, size_t n) {
        assert( m <= n && n <= __repr.__length);
        auto res = Buffer!T();
        if ( m == n ) {
            res.__repr = new Repr;
            return res;
        }
        res.__repr = new Repr(this.__repr);
        res.popBackN(res.length-n);
        res.popFrontN(m);
        return res;
    }
//    ptrdiff_t countUntil(in T[] needle) const pure @safe {
//        ptrdiff_t haystackpos, needlepos;
//        while(haystackpos < length) {
//            if ( opIndex(haystackpos) == needle[needlepos] ) {
//
//                return haystackpos;
//            } else {
//                needlepos = 0;
//                haystackpos++;
//            }
//        }
//        return -1;
//    }
    @property auto data(U=T[])() const pure {
        Appender!(T[]) a;
        if ( __repr && __repr.__buffer ) {
            foreach(ref b; __repr.__buffer) {
                a.put(b);
            }
        }
        static if ( is(U==T[]) ) {
            return a.data;
        } else {
            return castFrom!(T[]).to!U(a.data);
        }
    }
    string opCast(string)() {
        return this.toString;
    }
    bool opEquals(U)(U x) {
        return cast(U)this == x;
    }
}
///
public unittest {

    static assert(isInputRange!(Buffer!ubyte));
    static assert(isForwardRange!(Buffer!ubyte));
    static assert(hasLength!(Buffer!ubyte));
    static assert(hasSlicing!(Buffer!ubyte));
    static assert(isBidirectionalRange!(Buffer!ubyte));
    static assert(isRandomAccessRange!(Buffer!ubyte));
    
    auto b = Buffer!ubyte();
    b.put("abc".representation.dup);
    b.put("def".representation.dup);
    assert(b.length == 6);
    assert(b.toString == "abcdef");
    assert(b.front == 'a');
    assert(b.back == 'f');
    assert(equal(b[0..$], "abcdef"));
    assert(equal(b[$-2..$], "ef"));
    assert(b == "abcdef");
    b.popFront;
    b.popBack;
    assert(b.front == 'b');
    assert(b.back == 'e');
    assert(b.length == 4);
    assert(retro(b).front == 'e');
    assert(countUntil(b, 'e') == 3);
    assert(equal(splitter(b, 'c').array[1], ['d', 'e'])); // split "bcde" on 'c'
    assert(equal(b, "bcde"));
    b.popFront; b.popFront;
    assert(b.front == 'd');
    assert(b.front == b[0]);
    assert(b.back == b[$-1]);

    auto c = Buffer!ubyte();
    c.put("Header0: value0\n".representation.dup);
    c.put("Header1: value1\n".representation.dup);
    c.put("Header2: value2\n\nbody".representation.dup);
    auto c_length = c.length;
    auto eoh = countUntil(c, "\n\n");
    assert(eoh == 47);
    foreach(header; c[0..eoh].splitter('\n') ) {
        writeln(castFrom!(ubyte[]).to!(string)(header.data));
    }
    assert(equal(findSplit(c, "\n\n")[2], "body"));
    assert(c.length == c_length);
}

extern(C) {
    int SSL_library_init();
    void OpenSSL_add_all_ciphers();
    void OpenSSL_add_all_digests();
    void SSL_load_error_strings();
    
    struct SSL {}
    struct SSL_CTX {}
    struct SSL_METHOD {}
    
    SSL_CTX* SSL_CTX_new(const SSL_METHOD* method);
    SSL* SSL_new(SSL_CTX*);
    int SSL_set_fd(SSL*, int);
    int SSL_connect(SSL*);
    int SSL_write(SSL*, const void*, int);
    int SSL_read(SSL*, void*, int);
    int SSL_shutdown(SSL*) @trusted @nogc nothrow;
    void SSL_free(SSL*);
    void SSL_CTX_free(SSL_CTX*);
    
    long    SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg);
    
    long SSL_CTX_set_mode(SSL_CTX *ctx, long mode);
    long SSL_set_mode(SSL *ssl, long mode);
    
    long SSL_CTX_get_mode(SSL_CTX *ctx);
    long SSL_get_mode(SSL *ssl);
    
    SSL_METHOD* SSLv3_client_method();
    SSL_METHOD* TLSv1_2_client_method();
    SSL_METHOD* TLSv1_client_method();
}

//pragma(lib, "crypto");
//pragma(lib, "ssl");

shared static this() {
    SSL_library_init();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
    SSL_load_error_strings();
}

public class OpenSslSocket : Socket {
    enum SSL_MODE_RELEASE_BUFFERS = 0x00000010L;
    private SSL* ssl;
    private SSL_CTX* ctx;
    private void initSsl() {
        //ctx = SSL_CTX_new(SSLv3_client_method());
        ctx = SSL_CTX_new(TLSv1_client_method());
        assert(ctx !is null);
        
        //SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
        //SSL_CTX_ctrl(ctx, 33, SSL_MODE_RELEASE_BUFFERS, null);
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, this.handle);
    }
    
    @trusted
    override void connect(Address to) {
        super.connect(to);
        if(SSL_connect(ssl) == -1)
            throw new Exception("ssl connect failed");
    }
    
    @trusted
    override ptrdiff_t send(const(void)[] buf, SocketFlags flags) {
        return SSL_write(ssl, buf.ptr, cast(uint) buf.length);
    }
    override ptrdiff_t send(const(void)[] buf) {
        return send(buf, SocketFlags.NONE);
    }
    @trusted
    override ptrdiff_t receive(void[] buf, SocketFlags flags) {
        return SSL_read(ssl, buf.ptr, cast(int)buf.length);
    }
    override ptrdiff_t receive(void[] buf) {
        return receive(buf, SocketFlags.NONE);
    }
    this(AddressFamily af, SocketType type = SocketType.STREAM) {
        super(af, type);
        initSsl();
    }
    
    this(socket_t sock, AddressFamily af) {
        super(sock, af);
        initSsl();
    }
    override void close() {
        //SSL_shutdown(ssl);
        super.close();
    }
    ~this() {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }
}

public abstract class SocketStream {
    private {
        Duration timeout;
        Socket   s;
        bool     __isOpen;
        bool     __isConnected;
    }
    void open(AddressFamily fa) {
    }
    @property ref Socket so() pure {
        return s;
    }
    @property bool isOpen() @safe @nogc pure const {
        return s && __isOpen;
    }
    @property bool isConnected() @safe @nogc pure const {
        return s && __isConnected;
    }
    void close() {
        tracef("Close socket");
        if ( isOpen ) {
            s.close();
            __isOpen = false;
            __isConnected = false;
        }
        s = null;
    }
    
    auto connect(string host, ushort port, Duration timeout = 10.seconds) {
        tracef(format("Create connection to %s:%d", host, port));
        Address[] addresses;
        __isConnected = false;
        try {
            addresses = getAddress(host, port);
        } catch (Exception e) {
            errorf("Failed to connect: can't resolve %s - %s", host, e.msg);
            throw new ConnectError("Can't connect to %s:%d: %s".format(host, port, e.msg));
        }
        foreach(a; addresses) {
            tracef("Trying %s", a);
            try {
                open(a.addressFamily);
                s.setOption(SocketOptionLevel.SOCKET, SocketOption.SNDTIMEO, timeout);
                s.connect(a);
                tracef("Connected to %s", a);
                __isConnected = true;
                break;
            } catch (SocketException e) {
                warningf("Failed to connect to %s:%d(%s): %s", host, port, a, e.msg);
                s.close();
            }
        }
        if ( !__isConnected ) {
            throw new ConnectError("Can't connect to %s:%d".format(host, port));
        }
        return this;
    }
    
    ptrdiff_t send(const(void)[] buff)
    in {assert(isConnected);}
    body {
        return s.send(buff);
    }
    
    ptrdiff_t receive(void[] buff) {
        auto r = s.receive(buff);
        if ( r > 0 ) {
            buff.length = r;
        }
        return r;
    }
}

public class SSLSocketStream: SocketStream {
    override void open(AddressFamily fa) {
        if ( s !is null ) {
            s.close();
        }
        s = new OpenSslSocket(fa);
        assert(s !is null, "Can't create socket");
        __isOpen = true;
    }
}

public class TCPSocketStream : SocketStream {
    override void open(AddressFamily fa) {
        if ( s !is null ) {
            s.close();
        }
        s = new Socket(fa, SocketType.STREAM, ProtocolType.TCP);
        assert(s !is null, "Can't create socket");
        __isOpen = true;
    }
}

