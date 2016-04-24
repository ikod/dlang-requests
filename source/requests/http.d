
module requests.http;

import std.algorithm;
import std.array;
import std.conv;
import std.datetime;
import std.exception;
import std.format;
import std.stdio;
import std.range;
import std.socket;
import std.string;
import std.traits;
import std.typecons;
import std.experimental.logger;
import core.thread;
import core.stdc.errno;
import requests.streams;
import requests.uri;
import requests.utils;

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

pragma(lib, "crypto");
pragma(lib, "ssl");

shared static this() {
    SSL_library_init();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
    SSL_load_error_strings();
}

class OpenSslSocket : Socket {
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

unittest {
    struct S {
        private {
            int    __i;
            string __s;
            bool   __b;
        }
        mixin(getter("i"));
        mixin(setter("i"));
        mixin(getter("b"));
    }
    S s;
    assert(s.i == 0);
    s.i = 1;
    assert(s.i == 1);
    assert(s.b == false);
}

class RequestException: Exception {
    this(string msg, string file = __FILE__, size_t line = __LINE__) @safe pure {
        super(msg, file, line);
    }
}

class ConnectError: Exception {
    this(string msg, string file = __FILE__, size_t line = __LINE__) @safe pure {
        super(msg, file, line);
    }
}

class TimeoutException: Exception {
    this(string msg, string file = __FILE__, size_t line = __LINE__) @safe pure {
        super(msg, file, line);
    }
}

interface Auth {
    string[string] authHeaders(string domain);
}

class BasicAuthentication: Auth {
    private {
        string   _username, _password;
        string[] _domains;
    }
    this(string username, string password, string[] domains = []) {
        _username = username;
        _password = password;
        _domains = domains;
    }
    override string[string] authHeaders(string domain) {
        import std.base64;
        string[string] auth;
        auth["Authorization"] = "Basic " ~ to!string(Base64.encode(cast(ubyte[])"%s:%s".format(_username, _password)));
        return auth;
    }
}


abstract class SocketStream {
    private {
        Duration timeout;
        Socket   s;
        bool     __isOpen;
        bool     __isConnected;
    }
    void reopen() {
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

    auto connect(string host, short port, Duration timeout = 10.seconds)
    in {assert(isOpen);}
    body {
        tracef(format("Create connection to %s:%d", host, port));
        Address[] addresses;
        __isConnected = false;
        try {
            addresses = getAddress(host, port);
        } catch (Exception e) {
            errorf("Can't resolve %s - %s", host, e.msg);
            return this;
        }
        s.setOption(SocketOptionLevel.SOCKET, SocketOption.SNDTIMEO, timeout);
        foreach(a; addresses) {
            tracef("Trying %s", a);
            try {
                s.connect(a);
                tracef("Connected to %s", a);
                __isConnected = true;
                break;
            } catch (SocketException e) {
                errorf("Failed to connect: %s", e.msg);
            }
            reopen();
            s.setOption(SocketOptionLevel.SOCKET, SocketOption.SNDTIMEO, timeout);
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

class SSLSocketStream: SocketStream {
    this() {
        s = new OpenSslSocket(AddressFamily.INET);
        assert(s !is null, "Can't create ssl socket");
        __isOpen = true;
    }
    override void reopen() {
        s.close();
        s = new OpenSslSocket(AddressFamily.INET);
    }
}
class TCPSocketStream : SocketStream {
    this() {
        s = new Socket(AddressFamily.INET, SocketType.STREAM, ProtocolType.TCP);
        assert(s !is null, "Can't create socket");
        __isOpen = true;
    }
    override void reopen() {
        s.close();
        s = new Socket(AddressFamily.INET, SocketType.STREAM, ProtocolType.TCP);
    }
}
///
/// Response - this is result of request
///
/// Response.code - response code
/// Response.responseBody - container for received body
///  
struct Response {
    private {
        ushort         __code;
        string         __status_line;
        string[string] __responseHeaders;
        Buffer!ubyte   __responseBody;
        Response[]     __history; // redirects history
        SysTime        __startedAt, __connectedAt, __requestSentAt, __finishedAt;
    }
   ~this() {
        __responseHeaders = null;
        __history.length = 0;
    }
    mixin(getter("code"));
    mixin(getter("status_line"));
    mixin(getter("responseHeaders"));
    @property auto responseBody() pure const @safe {
        return __responseBody;
    }
    mixin(getter("history"));
    private {
        mixin(setter("code"));
        mixin(setter("status_line"));
        mixin(setter("responseHeaders"));
        mixin(setter("responseBody"));
    }
    @property auto getStats() const pure @safe {
        alias statTuple = Tuple!(Duration, "connectTime",
                                 Duration, "sendTime",
                                 Duration, "recvTime");
        statTuple stat;
        stat.connectTime = __connectedAt - __startedAt;
        stat.sendTime = __requestSentAt - __connectedAt;
        stat.recvTime = __finishedAt - __requestSentAt;
        return stat;
    }
}

template rank(R) {
    static if ( isInputRange!R ) {
        enum size_t rank = 1 + rank!(ElementType!R);
    } else {
        enum size_t rank = 0;
    }
}

unittest {
    assert(rank!(char) == 0);
    assert(rank!(string) == 1);
}

struct PostFile {
    string fileName;     // name of the file to send
    string fieldName;    // name of the field (if empty - send file base name)
    string contentType;  // contentType of the file if not empty
}
///
/// Request main structure
///
struct Request {
    private {
        string         __method = "GET";
        URI            __uri;
        string[string] __headers;
        Auth           __authenticator;
        uint           __keepAlive = 0;
        uint           __maxRedirects = 10;
        size_t         __maxHeadersLength = 32 * 1024; // 16 KB
        size_t         __maxContentLength = 5 * 1024 * 1024; // 5MB
        ptrdiff_t      __contentLength;
        SocketStream   __stream;
        Duration       __timeout = 30.seconds;
        Response       __response;
        Response[]     __history; // redirects history
        size_t         __bufferSize = 16*1024; // 16k
        uint           __verbosity = 0;  // 0 - no output, 1 - headers, 2 - headers+body info
        DataPipe!ubyte __bodyDecoder;
        DecodeChunked  __unChunker;
    }

    mixin(getter("keepAlive"));
    mixin(setter("keepAlive"));
    mixin(getter("method"));
    mixin(setter("method"));
    mixin(getter("timeout"));
    mixin(setter("timeout"));
    mixin(setter("authenticator"));
    mixin(getter("maxContentLength"));
    mixin(setter("maxContentLength"));
    mixin(getter("maxRedirects"));
    mixin(setter("maxRedirects"));
    mixin(getter("maxHeadersLength"));
    mixin(setter("maxHeadersLength"));
    mixin(getter("bufferSize"));
    mixin(setter("bufferSize"));
    mixin(getter("verbosity"));
    mixin(setter("verbosity"));

    this(string uri) {
        __uri = URI(uri);
    }
   ~this() {
        if ( __stream && __stream.isConnected) {
            __stream.close();
        }
        __stream = null;
        __headers = null;
        __authenticator = null;
        __history = null;
    }

    void addHeaders(in string[string] headers) {
        foreach(pair; headers.byKeyValue) {
            __headers[pair.key] = pair.value;
        }
    }

    @property string[string] headers() {
        string[string] generatedHeaders;
        if ( __authenticator ) {
            foreach(pair; __authenticator.authHeaders(__uri.host).byKeyValue) {
                generatedHeaders[pair.key] = pair.value;
            }
        }

        generatedHeaders["Connection"] = __keepAlive?"Keep-Alive":"Close";
        generatedHeaders["Host"] = __uri.host;
        if ( __uri.scheme !in standard_ports || __uri.port != standard_ports[__uri.scheme] ) {
            generatedHeaders["Host"] ~= ":%d".format(__uri.port);
        }
        foreach(pair; __headers.byKeyValue) {
            generatedHeaders[pair.key] = pair.value;
        }
        return generatedHeaders;
    }

    @property string requestString(string[string] params = null) {
        if ( __method != "GET" ) {
            // encode params into url only for GET
            return "%s %s HTTP/1.1\r\n".format(__method, __uri.path);
        }
        auto query = __uri.query.dup;
        if ( params ) {
            query ~= params2query(params);
            if ( query[0] != '?' ) {
                query = "?" ~ query;
            }
        }
        return "%s %s%s HTTP/1.1\r\n".format(__method, __uri.path, query);
    }
    static string urlEncoded(string p) pure @safe {
        string[dchar] translationTable = [
            ' ':  "%20", '!': "%21", '*': "%2A",
            '\'': "%27", '(': "%28", ')': "%29",
            ';':  "%3B", ':': "%3A", '@': "%40",
            '&':  "%26", '=': "%3D", '+': "%2B",
            '$':  "%24", ',': "%2C", '/': "%2F",
            '?':  "%3F", '#': "%23", '[': "%5B",
            ']':  "%5D", '%': "%25",
        ];
        return translate(p, translationTable);
    }
    unittest {
        assert(urlEncoded(`abc !#$&'()*+,/:;=?@[]`) == "abc%20%21%23%24%26%27%28%29%2A%2B%2C%2F%3A%3B%3D%3F%40%5B%5D");
    }
    static string params2query(string[string] params) {
        auto m = params.keys.
                        sort().
                        map!(a=>urlEncoded(a) ~ "=" ~ urlEncoded(params[a])).
                        join("&");
        return m;
    }

    auto analyzeHeaders(in string[string] headers) {

        __contentLength = -1;
        __unChunker = null;
        auto contentLength = "content-length" in headers;
        if ( contentLength ) {
            try {
                __contentLength = to!ptrdiff_t(*contentLength);
                if ( __contentLength > maxContentLength) {
                    throw new RequestException("ContentLength > maxContentLength (%d>%d)".
                                format(__contentLength, __maxContentLength));
                }
            } catch (ConvException e) {
                throw new RequestException("Can't convert Content-Length from %s".format(*contentLength));
            }
        }
        auto transferEncoding = "transfer-encoding" in headers;
        if ( transferEncoding ) {
            tracef("transferEncoding: %s", *transferEncoding);
            if ( *transferEncoding == "chunked") {
                __unChunker = new DecodeChunked();
                __bodyDecoder.insert(__unChunker);
            }
        }
        auto contentEncoding = "content-encoding" in headers;
        if ( contentEncoding ) {
            tracef("decode from: %s", *contentEncoding);
            if ( *contentEncoding == "gzip" ) {
                __bodyDecoder.insert(new Decompressor!ubyte);
            }
            if ( *contentEncoding == "deflate" ) {
                __bodyDecoder.insert(new Decompressor!ubyte);
            }
        }
    }

    void parseResponseHeaders(ref Buffer!ubyte buffer) {
        string lastHeader;
        foreach(line; buffer.data!(string).split("\n").map!(l => l.stripRight)) {
            if ( ! __response.status_line.length ) {
                tracef("statusLine: %s", line);
                __response.status_line = line;
                if ( __verbosity >= 1 ) {
                    writefln("< %s", line);
                }
                auto parsed = line.split(" ");
                if ( parsed.length >= 3 ) {
                    __response.code = parsed[1].to!ushort;
                }
                continue;
            }
            if ( line[0] == ' ' || line[0] == '\t' ) {
                // unfolding https://tools.ietf.org/html/rfc822#section-3.1
                auto stored = lastHeader in __response.__responseHeaders;
                if ( stored ) {
                    *stored ~= line;
                }
                continue;
            }
            auto parsed = line.findSplit(":");
            auto header = parsed[0].toLower;
            auto value = parsed[2].strip;
            auto stored = __response.responseHeaders.get(header, null);
            if ( stored ) {
                value = stored ~ ", " ~ value;
            }
            __response.__responseHeaders[header] = value;
            if ( __verbosity >= 1 ) {
                writefln("< %s: %s", parsed[0], value);
            }

            tracef("Header %s = %s", header, value);
            lastHeader = header;
        }
    }

    bool headersHaveBeenReceived(in ubyte[] data, ref Buffer!ubyte buffer, out string separator) {
        foreach(s; ["\r\n\r\n", "\n\n"]) {
            if ( data.canFind(s) || buffer.canFind(s) ) {
                separator = s;
                return true;
            }
        }
        return false;
    }

    bool followRedirectResponse() {
        __history ~= __response;
        if ( __history.length >= __maxRedirects ) {
            return false;
        }
        auto location = "location" in __response.responseHeaders;
        if ( !location ) {
            return false;
        }
        auto connection = "connection" in __response.__responseHeaders;
        if ( !connection || *connection == "close" ) {
            tracef("Closing connection because of 'Connection: close' or no 'Connection' header");
            __stream.close();
        }
        URI oldURI = __uri;
        URI newURI = oldURI;
        try {
            newURI = URI(*location);
        } catch (UriException e) {
            trace("Can't parse Location:, try relative uri");
            newURI.path = *location;
            newURI.uri = newURI.recalc_uri;
        }
        handleURLChange(oldURI, newURI);
        __uri = newURI;
        __response = Response.init;
        return true;
    }

    void handleURLChange(in URI from, in URI to) {
        if ( __stream !is null && __stream.isConnected && 
            ( from.scheme != to.scheme || from.host != to.host || from.port != to.port) ) {
            tracef("Have to reopen stream");
            __stream.close();
        }
    }
    
    void checkURL(string url, string file=__FILE__, size_t line=__LINE__) {
        if (url is null && __uri.uri == "" ) {
            throw new RequestException("No url configured", file, line);
        }
        
        if ( url !is null ) {
            URI newURI = URI(url);
            handleURLChange(__uri, newURI);
            __uri = newURI;
        }
    }

    void setupConnection() {
        if ( !__stream || !__stream.isConnected ) {
            tracef("Set up new connection");
            final switch (__uri.scheme) {
                case "http":
                    __stream = new TCPSocketStream().connect(__uri.host, __uri.port, __timeout);
                    break;
                case "https":
                    __stream = new SSLSocketStream().connect(__uri.host, __uri.port, __timeout);
                    break;
            }
        } else {
            tracef("Use old connection");
        }
    }

    void receiveResponse() {

        __stream.s.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, timeout);
        scope(exit) {
            __stream.s.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, 0.seconds);
        }

        __bodyDecoder = new DataPipe!ubyte();
        auto b = new ubyte[__bufferSize];
        scope(exit) {
            __bodyDecoder = null;
            __unChunker = null;
            b = null;
        }

        auto buffer = Buffer!ubyte();
        Buffer!ubyte ResponseHeaders, partialBody;
        size_t receivedBodyLength;
        ptrdiff_t read;
        string separator;
        
        while(true) {
            read = __stream.receive(b);
            tracef("read: %d", read);
            if ( read < 0 ) {
                if ( errno == EAGAIN ) {
                    throw new TimeoutException("Timeout receiving headers");
                }
                throw new ErrnoException("receiving Headers");
            }
            if ( read == 0 )
                break;
            
            auto data = b[0..read];
            buffer.put(data);
            if ( buffer.length > maxHeadersLength ) {
                throw new RequestException("Headers length > maxHeadersLength (%d > %d)".format(buffer.length, maxHeadersLength));
            }
            if ( headersHaveBeenReceived(data, buffer, separator) ) {
                auto s = buffer.data!(ubyte[]).findSplit(separator);
                ResponseHeaders = Buffer!ubyte(s[0]);
                partialBody = Buffer!ubyte(s[2]);
                receivedBodyLength += partialBody.length;
                parseResponseHeaders(ResponseHeaders);
                break;
            }
        }
        
        analyzeHeaders(__response.__responseHeaders);
        __bodyDecoder.put(partialBody);

        if ( __verbosity >= 2 ) {
            writefln("< %d bytes of body received", partialBody.length);
        }

        if ( __method == "HEAD" ) {
            // HEAD response have ContentLength, but have no body
            return;
        }

        while( true ) {
            if ( __contentLength >= 0 && receivedBodyLength >= __contentLength ) {
                trace("Body received.");
                break;
            }
            if ( __unChunker && __unChunker.done ) {
                break;
            }
            read = __stream.receive(b);
            if ( read < 0 ) {
                if ( errno == EAGAIN ) {
                    throw new TimeoutException("Timeout receiving body");
                }
                throw new ErrnoException("receiving body");
            }
            if ( __verbosity >= 2 ) {
                writefln("< %d bytes of body received", read);
            }
            tracef("read: %d", read);
            if ( read == 0 ) {
                trace("read done");
                break;
            }
            receivedBodyLength += read;
            __bodyDecoder.put(b[0..read].dup);
            __response.__responseBody.put(__bodyDecoder.get());
            tracef("receivedTotal: %d, contentLength: %d, bodyLength: %d", receivedBodyLength, __contentLength, __response.__responseBody.length);
        }
        __bodyDecoder.flush();
        __response.__responseBody.put(__bodyDecoder.get());
    }
    ///
    /// execute POST request.
    /// Send form-urlencoded data
    /// 
    /// Parameters:
    ///     url = url to request
    ///     rqData = data to send
    ///  Returns:
    ///     Response
    ///  Examples:
    ///  ------------------------------------------------------------------
    ///  rs = rq.exec!"POST"("http://httpbin.org/post", ["a":"b", "c":"d"]);
    ///  ------------------------------------------------------------------
    ///
    Response exec(string method)(string url, string[string] rqData) if (method=="POST") {
        //
        // application/x-www-form-urlencoded
        //
        __method = method;

        __response = Response.init;
        checkURL(url);
    connect:
        __response.__startedAt = Clock.currTime;
        setupConnection();
        
        if ( !__stream.isConnected() ) {
            return __response;
        }
        __response.__connectedAt = Clock.currTime;

        string encoded = params2query(rqData);
        auto h = headers;
        h["Content-Type"] = "application/x-www-form-urlencoded";
        h["Content-Length"] = to!string(encoded.length);

        Appender!string req;
        req.put(requestString());
        h.byKeyValue.
            map!(kv => kv.key ~ ": " ~ kv.value ~ "\r\n").
                each!(h => req.put(h));
        req.put("\r\n");
        req.put(encoded);
        trace(req);

        if ( __verbosity >= 1 ) {
            req.data.splitLines.each!(a => writeln("> " ~ a));
        }

        auto rc = __stream.send(req.data());
        if ( rc == -1 ) {
            errorf("Error sending request: ", lastSocketError);
            return __response;
        }
        __response.__requestSentAt = Clock.currTime;

        receiveResponse();

        __response.__finishedAt = Clock.currTime;

        auto connection = "connection" in __response.__responseHeaders;
        if ( !connection || *connection == "close" ) {
            tracef("Closing connection because of 'Connection: close' or no 'Connection' header");
            __stream.close();
        }
        if ( canFind([302, 303], __response.__code) && followRedirectResponse() ) {
            if ( __method != "GET" ) {
                return this.get();
            }
            goto connect;
        }
        __response.__history = __history;
        return __response;
    }
    ///
    /// send file(s) using POST
    /// Parameters:
    ///     url = url
    ///     files = array of PostFile structures
    /// Returns:
    ///     Response
    /// Example:
    /// ---------------------------------------------------------------
    ///    PostFile[] files = [
    ///                   {fileName:"tests/abc.txt", fieldName:"abc", contentType:"application/octet-stream"}, 
    ///                   {fileName:"tests/test.txt"}
    ///               ];
    ///    rs = rq.exec!"POST"("http://httpbin.org/post", files);
    /// ---------------------------------------------------------------
    /// 
    Response exec(string method="POST")(string url, PostFile[] files) {
        import std.uuid;
        import std.file;
        //
        // application/json
        //
        __method = method;
        
        __response = Response.init;
        checkURL(url);
    connect:
        __response.__startedAt = Clock.currTime;
        setupConnection();
        
        if ( !__stream.isConnected() ) {
            return __response;
        }
        __response.__connectedAt = Clock.currTime;

        Appender!string req;
        req.put(requestString());
        
        string   boundary = randomUUID().toString;
        string[] partHeaders;
        size_t   contentLength;

        foreach(part; files) {
            string fieldName = part.fieldName ? part.fieldName : part.fileName;
            string h = "--" ~ boundary ~ "\r\n";
            h ~= `Content-Disposition: form-data; name="%s"; filename="%s"`.
                format(fieldName, part.fileName) ~ "\r\n";
            if ( part.contentType ) {
                h ~= "Content-Type: " ~ part.contentType ~ "\r\n";
            }
            h ~= "\r\n";
            partHeaders ~= h;
            contentLength += h.length + getSize(part.fileName) + "\r\n".length;
        }
        contentLength += "--".length + boundary.length + "--\r\n".length;

        auto h = headers;
        h["Content-Type"] = "multipart/form-data; boundary=" ~ boundary;
        h["Content-Length"] = to!string(contentLength);
        h.byKeyValue.
            map!(kv => kv.key ~ ": " ~ kv.value ~ "\r\n").
            each!(h => req.put(h));
        req.put("\r\n");
        
        trace(req);
        if ( __verbosity >= 1 ) {
            req.data.splitLines.each!(a => writeln("> " ~ a));
        }

        auto rc = __stream.send(req.data());
        if ( rc == -1 ) {
            errorf("Error sending request: ", lastSocketError);
            return __response;
        }
        foreach(hdr, f; zip(partHeaders, files)) {
            tracef("sending part headers <%s>", hdr);
            __stream.send(hdr);
            auto file = File(f.fileName, "rb");
            scope(exit) {
                file.close();
            }
            foreach(chunk; file.byChunk(16*1024)) {
                __stream.send(chunk);
            }
            __stream.send("\r\n");
        }
        __stream.send("--" ~ boundary ~ "--\r\n");
        __response.__requestSentAt = Clock.currTime;

        receiveResponse();

        __response.__finishedAt = Clock.currTime;
        ///
        auto connection = "connection" in __response.__responseHeaders;
        if ( !connection || *connection == "close" ) {
            tracef("Closing connection because of 'Connection: close' or no 'Connection' header");
            __stream.close();
        }
        if ( canFind([302, 303], __response.__code) && followRedirectResponse() ) {
            if ( __method != "GET" ) {
                return this.get();
            }
            goto connect;
        }
        __response.__history = __history;
        ///
        return __response;
    }
    ///
    /// POST data from some string(with Content-Length), or from range of strings (use Transfer-Encoding: chunked)
    /// 
    /// Parameters:
    ///    url = url
    ///    content = string or input range
    ///    contentType = content type
    ///  Returns:
    ///     Response
    ///  Examples:
    ///      rs = rq.exec!"POST"("http://httpbin.org/post", "привiт, свiт!", "application/octet-stream");
    ///      
    ///      auto s = lineSplitter("one,\ntwo,\nthree.");
    ///      rs = rq.exec!"POST"("http://httpbin.org/post", s, "application/octet-stream");
    ///      
    ///      auto s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    ///      rs = rq.exec!"POST"("http://httpbin.org/post", s.representation.chunks(10), "application/octet-stream");
    ///
    ///      auto f = File("tests/test.txt", "rb");
    ///      rs = rq.exec!"POST"("http://httpbin.org/post", f.byChunk(3), "application/octet-stream");
    ///      
    Response exec(string method="POST", R)(string url, R content, string contentType="text/html")
        if ( isSomeString!R
            || (rank!R == 2 && isSomeChar!(Unqual!(typeof(content.front.front)))) 
            || (rank!R == 2 && (is(Unqual!(typeof(content.front.front)) == ubyte)))
            )
    {
        //
        // application/json
        //
        __method = method;
        
        __response = Response.init;
        checkURL(url);
    connect:
        __response.__startedAt = Clock.currTime;
        setupConnection();
        
        if ( !__stream.isConnected() ) {
            return __response;
        }
        __response.__connectedAt = Clock.currTime;

        Appender!string req;
        req.put(requestString());

        auto h = headers;
        h["Content-Type"] = contentType;
        static if ( isSomeString!R ) {
            h["Content-Length"] = to!string(content.length);
        } else {
            h["Transfer-Encoding"] = "chunked";
        }
        h.byKeyValue.
            map!(kv => kv.key ~ ": " ~ kv.value ~ "\r\n").
            each!(h => req.put(h));
        req.put("\r\n");

        trace(req);
        if ( __verbosity >= 1 ) {
            req.data.splitLines.each!(a => writeln("> " ~ a));
        }

        auto rc = __stream.send(req.data());
        if ( rc == -1 ) {
            errorf("Error sending request: ", lastSocketError);
            return __response;
        }

        static if ( isSomeString!R ) {
            __stream.send(content);
        } else {
            while ( !content.empty ) {
                auto chunk = content.front;
                auto chunkHeader = "%x\r\n".format(chunk.length);
                tracef("sending %s%s", chunkHeader, chunk);
                __stream.send(chunkHeader);
                __stream.send(chunk);
                __stream.send("\r\n");
                content.popFront;
            }
            tracef("sent");
            __stream.send("0\r\n\r\n");
        }
        __response.__requestSentAt = Clock.currTime;

        receiveResponse();

        __response.__finishedAt = Clock.currTime;

        ///
        auto connection = "connection" in __response.__responseHeaders;
        if ( !connection || *connection == "close" ) {
            tracef("Closing connection because of 'Connection: close' or no 'Connection' header");
            __stream.close();
        }
        if ( canFind([302, 303], __response.__code) && followRedirectResponse() ) {
            if ( __method != "GET" ) {
                return this.get();
            }
            goto connect;
        }
        ///
        __response.__history = __history;
        return __response;
    }
    ///
    /// Send request without data
    /// Request parameters will be encoded into request string
    /// Parameters:
    ///     url = url
    ///     params = request parameters
    ///  Returns:
    ///     Response
    ///  Examples:
    ///     rs = Request().exec!"GET"("http://httpbin.org/get", ["c":"d", "a":"b"]);
    ///     
    Response exec(string method="GET")(string url = null, string[string] params = null) if (method != "POST")
    {

        __method = method;
        __response = Response.init;
        __history.length = 0;

        checkURL(url);

    connect:
        __response.__startedAt = Clock.currTime;
        setupConnection();

        if ( !__stream.isConnected() ) {
            return __response;
        }
        __response.__connectedAt = Clock.currTime;

        Appender!string req;
        req.put(requestString(params));
        headers.byKeyValue.
            map!(kv => kv.key ~ ": " ~ kv.value ~ "\r\n").
            each!(h => req.put(h));
        req.put("\r\n");
        trace(req);

        if ( __verbosity >= 1 ) {
            req.data.splitLines.each!(a => writeln("> " ~ a));
        }
        auto rc = __stream.send(req.data());
        if ( rc == -1 ) {
            errorf("Error sending request: ", lastSocketError);
            return __response;
        }
        __response.__requestSentAt = Clock.currTime;

        receiveResponse();

        __response.__finishedAt = Clock.currTime;

        ///
        auto connection = "connection" in __response.__responseHeaders;
        if ( !connection || *connection == "close" ) {
            tracef("Closing connection because of 'Connection: close' or no 'Connection' header");
            __stream.close();
        }
        if ( __verbosity >= 1 ) {
            writeln(">> Connect time: ", __response.__connectedAt - __response.__startedAt);
            writeln(">> Request send time: ", __response.__requestSentAt - __response.__connectedAt);
            writeln(">> Response recv time: ", __response.__finishedAt - __response.__requestSentAt);
        }
        if ( canFind([302, 303], __response.__code) && followRedirectResponse() ) {
            if ( __method != "GET" ) {
                return this.get();
            }
            goto connect;
        }
        ///
        __response.__history = __history;
        return __response;
    }

    Response get(string url = null, string[string] params = null, string file=__FILE__, size_t line=__LINE__) {
        __method = "GET";
        return exec(url, params);
    }
    
}

unittest {
    import std.json;
    globalLogLevel(LogLevel.info);
    tracef("http tests - start");
    assert(Request.params2query(["c ":"d", "a":"b"])=="a=b&c%20=d");

    auto rq = Request();
    auto rs = rq.get("https://httpbin.org/");
    assert(rs.code==200);
    assert(rs.responseBody.length > 0);
    rs = Request().get("http://httpbin.org/get", ["c":" d", "a":"b"]);
    assert(rs.code == 200);
    auto json = parseJSON(rs.responseBody.data).object["args"].object;
    assert(json["c"].str == " d");
    assert(json["a"].str == "b");

    globalLogLevel(LogLevel.info);
    rq = Request();
    rq.keepAlive = 5;
    // handmade json
    info("Check POST json");
    rs = rq.exec!"POST"("http://httpbin.org/post", `{"a":"☺ ", "c":[1,2,3]}`, "application/json");
    assert(rs.code==200);
    json = parseJSON(rs.responseBody.data).object["json"].object;
    assert(json["a"].str == "☺ ");
    assert(json["c"].array.map!(a=>a.integer).array == [1,2,3]);
    {
        // files
        globalLogLevel(LogLevel.info);
        info("Check POST files");
        PostFile[] files = [
                        {fileName:"tests/abc.txt", fieldName:"abc", contentType:"application/octet-stream"}, 
                        {fileName:"tests/test.txt"}
                    ];
        rs = rq.exec!"POST"("http://httpbin.org/post", files);
        assert(rs.code==200);
    }
    {
        // string
        info("Check POST utf8 string");
        rs = rq.exec!"POST"("http://httpbin.org/post", "привiт, свiт!", "application/octet-stream");
        assert(rs.code==200);
        auto data = parseJSON(rs.responseBody.data).object["data"].str;
        assert(data=="привiт, свiт!");
    }
    // ranges
    {
        info("Check POST chunked from lineSplitter");
        auto s = lineSplitter("one,\ntwo,\nthree.");
        rs = rq.exec!"POST"("http://httpbin.org/post", s, "application/octet-stream");
        assert(rs.code==200);
        auto data = parseJSON(rs.responseBody.data).object["data"].str;
        assert(data=="one,two,three.");
    }
    {
        info("Check POST chunked from array");
        auto s = ["one,", "two,", "three."];
        rs = rq.exec!"POST"("http://httpbin.org/post", s, "application/octet-stream");
        assert(rs.code==200);
        auto data = parseJSON(rs.responseBody.data).object["data"].str;
        assert(data=="one,two,three.");
    }
    {
        info("Check POST chunked using std.range.chunks()");
        auto s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        rs = rq.exec!"POST"("http://httpbin.org/post", s.representation.chunks(10), "application/octet-stream");
        assert(rs.code==200);
        auto data = parseJSON(rs.responseBody.data).object["data"].str;
        assert(data==s);
    }
    {
        info("Check POST chunked from file.byChunk");
        auto f = File("tests/test.txt", "rb");
        rs = rq.exec!"POST"("http://httpbin.org/post", f.byChunk(3), "application/octet-stream");
        assert(rs.code==200);
        auto data = parseJSON(rs.responseBody.data).object["data"].str;
        assert(data=="abcdefgh\n12345678\n");
        f.close();
    }
    // associative array
    rs = rq.exec!"POST"("http://httpbin.org/post", ["a":"b ", "c":"d"]);
    assert(rs.code==200);
    auto form = parseJSON(rs.responseBody.data).object["form"].object;
    assert(form["a"].str == "b ");
    assert(form["c"].str == "d");
    info("Check HEAD");
    rs = rq.exec!"HEAD"("http://httpbin.org/");
    assert(rs.code==200);
    info("Check DELETE");
    rs = rq.exec!"DELETE"("http://httpbin.org/delete");
    assert(rs.code==200);
    info("Check PUT");
    rs = rq.exec!"PUT"("http://httpbin.org/put",  `{"a":"b", "c":[1,2,3]}`, "application/json");
    assert(rs.code==200);
    info("Check PATCH");
    rs = rq.exec!"PATCH"("http://httpbin.org/patch", "привiт, свiт!", "application/octet-stream");
    assert(rs.code==200);

    info("Check compressed content");
    globalLogLevel(LogLevel.info);
    rq = Request();
    rq.keepAlive = 5;
    rq.addHeaders(["Accept-Encoding":"gzip"]);
    rs = rq.get("http://httpbin.org/gzip");
    assert(rs.code==200);
    info("gzip - ok");
    rq.addHeaders(["Accept-Encoding":"deflate"]);
    rs = rq.get("http://httpbin.org/deflate");
    assert(rs.code==200);
    info("deflate - ok");

    info("Check redirects");
    globalLogLevel(LogLevel.info);
    rq = Request();
    rq.keepAlive = 5;
    rs = rq.exec!"GET"("http://httpbin.org/relative-redirect/2");
    assert(rs.history.length == 2);
    assert(rs.code==200);
//    rq = Request();
    rq.keepAlive = 5;
    rs = rq.exec!"GET"("http://httpbin.org/absolute-redirect/2");
    assert(rs.history.length == 2);
    assert(rs.code==200);
//    rq = Request();
    rq.maxRedirects = 2;
    rs = rq.exec!"GET"("http://httpbin.org/absolute-redirect/3");
    assert(rs.history.length == 2);
    assert(rs.code==302);

    info("Check utf8 content");
    globalLogLevel(LogLevel.info);
    rq = Request();
    rs = rq.get("http://httpbin.org/encoding/utf8");
    assert(rs.code==200);

    info("Check chunked content");
    globalLogLevel(LogLevel.info);
    rq = Request();
    rq.keepAlive = 5;
    rq.bufferSize = 16*1024;
    rs = rq.get("http://httpbin.org/range/1024");
    assert(rs.code==200);
    assert(rs.responseBody.length==1024);

    info("Check basic auth");
    globalLogLevel(LogLevel.info);
    rq = Request();
    rq.authenticator = new BasicAuthentication("user", "passwd");
    rs = rq.get("http://httpbin.org/basic-auth/user/passwd");
    assert(rs.code==200);
 
    globalLogLevel(LogLevel.info);
    info("Check exception handling, error messages are OK");
    rq = Request();
    rq.timeout = 1.seconds;
    assertThrown!TimeoutException(rq.get("http://httpbin.org/delay/3"));
    assertThrown!ConnectError(rq.get("http://0.0.0.0:65000/"));
    assertThrown!ConnectError(rq.get("http://1.1.1.1/"));

    globalLogLevel(LogLevel.info);
    info("Check limits");
    rq = Request();
    rq.maxContentLength = 1;
    assertThrown!RequestException(rq.get("http://httpbin.org/"));
    rq = Request();
    rq.maxHeadersLength = 1;
    assertThrown!RequestException(rq.get("http://httpbin.org/"));
    rq = Request();
    tracef("http tests - ok");
}
