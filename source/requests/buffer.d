module requests.buffer;

import std.string:representation;
import std.algorithm;
import std.conv;
import std.range;
import std.stdio;
import std.traits;
import std.format;
import core.exception;
import std.exception;
import std.range.primitives;
import std.experimental.logger;

///
// network buffer
///

static immutable Exception RangeEmpty = new Exception("try to pop from empty Buffer");
static immutable Exception IndexOutOfRange = new Exception("Index out of range");
static immutable Exception BufferError = new Exception("Buffer internal ctruct corrupted");

// цели
// 1 минимум коприрований данных
// 2 input range interface
// 3 не держать ненужные данные в памяти
// сценарии использования
// чтение из сокеты во временный буффер, добавление временного буффера к Buffer
// проверили что Buffer содержит нужные данные, разделяет Buffer на части и продолжает рабботу.
//
//               +---B--+
// +---A--+      | data |
// | data |      +------+
// +------+  -> 
// | rest |      +---C--+
// +------+      | rest |
//               +------+
// приём данных продолжаем в Buffer C, для работы с полученными данными используем Buffer B
// 
public alias BufferChunk =       immutable(ubyte)[];
public alias BufferChunksArray = immutable(BufferChunk)[];

struct Buffer {

  package:
//    alias Chunk = BufferChunk;
    size_t              _length;
    BufferChunksArray   _chunks;
    size_t              _pos;       // offset from beginning, always points inside first chunk
    long                _end_pos;   // offset of the _length in the last chunk
 
  public:
    static struct _Range {
        // implement InputRange
        size_t              _pos;
        size_t              _end;
        Buffer              _buffer;
        this(in Buffer b) pure @safe @nogc nothrow {
            _buffer = b;
            _pos = 0;
            _end = _buffer.length;
        }
        @property auto ref front() const pure @safe @nogc nothrow {
            return _buffer[_pos];
        }
        @property void popFront() pure @safe @nogc {
            //enforce(!empty, "popFront from empty buffer");
            if ( empty ) {
                throw RangeEmpty;
            }
            _pos++;
        }
        @property void popFrontN(size_t n) pure @safe @nogc nothrow {
            _pos += min(n, length);
        }
        @property auto ref back() const pure @safe @nogc nothrow {
            return _buffer[_end-1];
        }
        @property auto popBack() pure @safe @nogc {
            //enforce(!empty, "popBack from empty buffer");
            if ( empty ) {
                throw RangeEmpty;
            }
            _end--;
        }
        @property void popBackN(size_t n) pure @safe @nogc nothrow {
            _end -= min(n, length);
        }
        @property bool empty() const pure @safe @nogc nothrow {
            return _pos == _end;
        }
        @property auto save() pure @safe @nogc nothrow {
            return this;
        }
        @property size_t length() const pure @safe @nogc nothrow {
            return _end - _pos;
        }
        auto ref opIndex(size_t i) const pure @safe @nogc {
            if ( i >= length ) {
                throw IndexOutOfRange;
            }
            return _buffer[_pos + i];
        }
        auto opSlice(size_t m, size_t n) const pure @safe {
            auto another = _buffer[m..n];
            return another.range();
        }
        auto opDollar() const pure @safe @nogc {
            return length;
        }
        // auto opCast(T)() const pure @safe if (is(T==immutable(ubyte)[])) {
        //     return _buffer[_pos.._end].data();
        // }
        // auto opCast(T)() const pure @safe if (is(T==ubyte[])) {
        //     return _buffer[_pos.._end].data().dup;
        // }
        auto opEquals(T)(T other) const pure @safe @nogc nothrow if (isSomeString!T) {
            if (other.length != length ) {
                return false;
            }
            size_t m = _pos, n = _end, i = 0;
            while( m > _buffer._chunks[i].length ) {
                auto l = _buffer._chunks[i].length;
                m -= l;
                n -= l;
                i++;
            }
            foreach(ref chunk; _buffer._chunks[i..$]) {
                auto cmp_len = min(n-m, chunk.length-m, other.length);
                if (chunk[m..m+cmp_len] != other[0..cmp_len]) {
                    return false;
                }
                m = 0;
                n -= cmp_len;
                if ( n == 0 ) {
                    break;
                }
                other = other[cmp_len..$];
            }
            return true;
        }
    }

    // this(string s) pure @safe nothrow immutable {
    //     _chunks = [s.representation];
    //     _length = s.length;
    //     _end_pos = _length;
    // }

    this(string s) pure @safe nothrow {
        _chunks = [s.representation];
        _length = s.length;
        _end_pos = _length;
    }

    this(BufferChunk s) pure @safe nothrow {
        _chunks = [s];
        _length = s.length;
        _end_pos = _length;
    }

    this(in Buffer other, size_t m, size_t n) pure @safe {
        ulong i;
        BufferChunksArray  content;
        // produce slice view m..n
        if ( n == m ) {
            return;
        }

        enforce(m < n && n <=other.length, "wrong m or n");
        assert(other._pos < other._chunks[0].length);
        m += other._pos;
        n += other._pos;

        _length = n - m;
        n = n - m;
        while( m > other._chunks[i].length ) {
            m -= other._chunks[i].length;
            i++;
        }
        auto to_copy = min(n, other._chunks[i].length - m);
        if ( to_copy > 0 ) {
            content ~= other._chunks[i][m..m+to_copy];
            _end_pos = to_copy;
        }
        i++;
        n -= to_copy;
        while(n > 0) {
            to_copy = min(n, other._chunks[i].length);
            content ~= other._chunks[i][0..to_copy];
            n -= to_copy;
            _end_pos = to_copy;
            i++;
        }
        _chunks = content;

    }

    this(in Buffer other, size_t m, size_t n) pure @safe immutable {
        ulong               i;
        BufferChunksArray   content;
        // produce slice view m..n
        if ( n == m ) {
            return;
        }

        enforce(m < n && n <=other.length, "wrong m or n");
        assert(other._pos < other._chunks[0].length);
        m += other._pos;
        n += other._pos;

        _length = n - m;
        n = n - m;
        while( m > other._chunks[i].length ) {
            m -= other._chunks[i].length;
            i++;
        }
        auto to_copy = min(n, other._chunks[i].length - m);
        if ( to_copy > 0 ) {
            content ~= other._chunks[i][m..m+to_copy];
        }
        i++;
        n -= to_copy;
        while(n > 0) {
            to_copy = min(n, other._chunks[i].length);
            content ~= other._chunks[i][0..to_copy];
            n -= to_copy;
            i++;
        }
        _chunks = content;
    }

    bool empty() const pure @safe @nogc nothrow {
        return _length == 0;
    }

    alias put = append;
    auto append(string s) pure @safe nothrow {
        if (s.length == 0 ) {
            return;
        }
        BufferChunk chunk = s.representation;
        if ( _chunks.length > 0 && _end_pos < _chunks[$-1].length ) {
            // we have to copy chunks with last chunk trimmed
            _chunks = _chunks[0..$-1] ~ _chunks[$-1][0.._end_pos];
        }
        _chunks ~= chunk;
        _length += chunk.length;
        _end_pos = s.length;
    }

    auto append(BufferChunk s) pure @safe nothrow {
        if (s.length == 0 ) {
            return;
        }
        if ( _chunks.length > 0 && _end_pos < _chunks[$-1].length ) {
            // we have to copy chunks with last chunk trimmed
            _chunks = _chunks[0..$-1] ~ _chunks[$-1][0.._end_pos];
        }
        _chunks ~= s;
        _length += s.length;
        _end_pos = s.length;
    }

    @property auto length() const pure @safe @nogc nothrow {
        return _length;
    }

    @property auto opDollar() const pure @safe @nogc nothrow {
        return _length;
    }

    Buffer opSlice(size_t m, size_t n) const pure @safe {
        if ( this._length==0 || m == n ) {
            return Buffer();
        }
        enforce( m <= n && n <= _length, "Wrong slice parameters: start: %d, end: %d, this.length: %d".format(m, n, _length));
        auto res = Buffer(this, m, n);
        return res;
    }

    @property ubyte opIndex(size_t n) const pure @safe @nogc nothrow {
        n += _pos;
        foreach(b; _chunks) {
            if ( n < b.length ) {
                return b[n];
            }
            n -= b.length;
        }
        // XXX
        // this is a way to have @nogc, while throwing RangeError
        // in case of wrong n value (n>=_length)
        return _chunks[$-1][$];
    }

    auto opEquals(T)(T other) const pure @safe @nogc nothrow if (isSomeString!T) {
        return this.range() == other;
    }

    @property auto save() pure @safe @nogc nothrow {
        return this;
    }

    alias front = frontByte;
    alias popFront = popFrontByte;
    @property ubyte frontByte() const pure @safe @nogc {
        assert(_pos < _chunks[0].length);
        return _chunks[0][_pos];
    }

    @property void popFrontByte() pure @safe @nogc {
        assert(_pos < _chunks[0].length);
        _pos++;
        _length--;
        if ( _pos >= _chunks[0].length ) {
            _pos = 0;
            _chunks = _chunks[1..$];
        }
    }

    BufferChunk frontChunk() pure @safe @nogc nothrow {
        return _chunks[0][_pos..$];
    }

    void popFrontChunk() pure @nogc @safe nothrow {
        assert(_pos < _chunks[0].length);
        _length -= _chunks[0].length - _pos;
        _pos = 0;
        _chunks = _chunks[1..$];
    }

    alias back = backByte;
    @property ubyte backByte() const pure @nogc @safe nothrow {
        return _chunks[$-1][_end_pos - 1];
    }
    @property void popBack() pure @safe @nogc {
        if ( _length == 0 ) {
            throw RangeEmpty;
        }
        if ( _end_pos > _chunks[$-1].length) {
            throw BufferError;
        }
        _length--;
        _end_pos--;
        if ( _end_pos == 0 && _length > 0) {
            _chunks.popBack;
            _end_pos = _chunks[$-1].length;
        }
    }
    BufferChunksArray dataChunks() const pure @safe nothrow {

        BufferChunksArray res;
        if ( _length == 0 ) {
            return res;
        }
        auto last_chunk = _chunks.length - 1;
        foreach(i,ref c; _chunks) {
            long a,b = c.length;
            if ( i == 0 ) {
                a = _pos;
            }
            if ( i == last_chunk ) {
                b = _end_pos;
            }
            res ~= c[a..b];
        }
        return res;
    }
    BufferChunk data() const pure @trusted {
        if ( _chunks.length == 0 ) {
            return BufferChunk.init;
        }
        if ( _chunks.length == 1 ) {
            return _chunks[0][_pos.._end_pos];
        }
        assert(_pos < _chunks[0].length);
        ubyte[] r = new ubyte[this.length];
        uint d = 0;
        size_t p = _pos;
        foreach(ref c; _chunks[0..$-1]) {
            r[d..d+c.length-p] = c[p..$];
            d += c.length-p;
            p = 0;
        }
        auto c = _chunks[$-1];
        r[d..$] = c[p.._end_pos];
        return assumeUnique(r);
    }
    Buffer find(alias pred="a==b")(char needle) const pure @safe {
        return find!pred(cast(ubyte)needle);
    }
    Buffer find(alias pred="a==b")(ubyte needle) const pure @safe {
        auto chunk_last = _chunks.length - 1;
        long chunk_pos = 0;
        foreach (i,ref c; _chunks) {
            long a,b;
            if (i == 0) {
                a = _pos;
            }
            if (i == chunk_last) {
                b = _end_pos;
            } else {
                b = c.length;
            }
            auto f = c[a..b].find!pred(needle);

            if ( f.length > 0) {
                auto p = b - f.length;
                return this[chunk_pos-_pos+p..$];
            }
            else {
                chunk_pos += c.length;
            }
        }
        return Buffer();
    }
    _Range range() const pure @safe @nogc nothrow {
        return _Range(this);
    }
    string toString() const @safe {
        return cast(string)data();
    }
    void describe() const @safe {
        writefln("leng: %d", _length);
        writefln("_pos: %d", _pos);
        writefln("_end: %d", _end_pos);
        writefln("chunks: %d", _chunks.length);
        foreach(ref c; _chunks) {
            writefln("%d bytes: %s", c.length, cast(string)c[0..min(10, c.length)]);
        }
    }
}

unittest {
    info("Test buffer");
    static assert(isInputRange!Buffer);
    static assert(isForwardRange!Buffer);
    static assert(hasLength!Buffer);
    static assert(hasSlicing!Buffer);
    static assert(isBidirectionalRange!Buffer);
    static assert(isRandomAccessRange!Buffer);
    auto b = Buffer();
    b.append("abc");
    b.append("def".representation);
    b.append("123");
    assert(equal(b.data(), "abcdef123"));
    assert(b == "abcdef123");

    auto bi = immutable Buffer("abc");
    assert(equal(bi.data(), "abc"));
    Buffer c = b;
    assert(cast(string)c.data() == "abcdef123");
    assert(c.length == 9);
    assert(c._chunks.length == 3);
    // update B do not affect C
    b.append("ghi");
    assert(cast(string)c.data() == "abcdef123");
    // test slices
    immutable Buffer di  = b[1..5];
    immutable Buffer dii = di[1..2];
    // +di+
    // |bc|
    // |de|
    // +--+
    assert(cast(string)di.data == "bcde");
    assert(equal(di.range.map!(c => cast(char)c), "bcde"));
    b = di[0..2];
    assert(cast(string)b.data, "ab");
    assert(b.length == 2);
    b = di[$-2..$];
    assert(cast(string)b.data == "de");
    assert(b._chunks.length==1);
    assert(b.length == 2);
    b = di[$-1..$];
    assert(cast(string)b.data == "e");
    assert(b._chunks.length==1);
    assert(b.length == 1);
    b = Buffer();
    b.append("abc");
    auto br = b.range();
    b.append("def".representation);
    b.append("123");
    assert(br=="abc");
    // +-b-+
    // |abc|
    // |def|
    // |123|
    // +---+
    assert(b._chunks.length==3);
    c = b[3..$];
    // +-c-+
    // |def|
    // |123|
    // +---+
    assert(c.length == 6);
    assert(c._chunks.length==2);
    assert(c[1] == 'e');
    assert(c[3] == '1');
    assert(c[$-1] == '3');

    static assert(hasLength!(Buffer));


    static assert(isInputRange!(Buffer._Range));
    static assert(isForwardRange!(Buffer._Range));
    static assert(hasLength!(Buffer._Range));
    static assert(hasSlicing!(Buffer._Range));
    static assert(isBidirectionalRange!(Buffer._Range));
    static assert(isRandomAccessRange!(Buffer._Range));
    auto bit = b.range();
    assert(!bit.canFind('4'));
    assert(bit.canFind('1'));
    assert(equal(splitter(bit, 'd').array[0], "abc"));
    assert(equal(splitter(bit, 'd').array[1], "ef123"));
    assert(bit.length == 9);
    assert(bit.front == 'a');
    assert(bit.back == '3');
    bit.popBack;
    assert(bit.front == 'a');
    assert(bit.back == '2');
    assert(bit[$-1] == '2');
    assert(bit.length == 8);
    assertThrown(bit[8]);
    assert(equal(bit, ['a', 'b', 'c', 'd', 'e', 'f', '1', '2']));
    assert(bit.countUntil('d')==3);
    assert(bit.countUntil('2')==7);
    assert(retro(bit).front == '2');
    bit.popFront();
    assert(equal(bit, ['b', 'c', 'd', 'e', 'f', '1', '2']));
    assert(bit == "bcdef12");
    bit.popFrontN(2);
    assert(equal(bit, ['d', 'e', 'f', '1', '2']));
    assert(bit == "def12");
    bit.popBackN(2);
    assert(equal(bit, ['d', 'e', 'f']));
    assert(bit.length == 3);
    assert(bit == "def");
    bit.popBackN(bit.length);
    assert(bit.length == 0);
    assert(bit == "");
    bit = b.range();
    assert(equal(bit, ['a', 'b', 'c', 'd', 'e', 'f', '1', '2', '3']));
    assert(equal(bit[1..4], "bcd"));

    b = Buffer("a\nb");
    assert(findSplit(b.range(), "\n")[2] == ['b']);
    b = Buffer("012");
    b.append("345");
    b.popFrontByte();
    assert(equal(b.data, "12345"));
    assert(equal(b[1..$-1].data, "234"));
    b.popFrontByte();
    assert(equal(b.data, "2345"));
    b.popFrontByte();
    assert(equal(b.data, "345"));
    b.popFrontByte();
    assert(equal(b.data, "45"));
    b = Buffer("012");
    b.append("345");
    auto bb = b;
    b.popFrontByte();
    assert(b[0]=='1');
    assert(b[$-1]=='5');
    assert(b.back == '5');
    assertThrown!RangeError(b[$]=='5');
    assert(equal(b[1..$-1], "234"));
    b.popFrontChunk();
    assert(equal(b.data, "345"));
    assert(b[0]=='3');
    assert(b[$-1]=='5');
    assert(equal(b[1..$-1], "4"));
    assert(equal(bb, "012345"));
    b.popFrontChunk();
    assertThrown!RangeError(b.popFrontChunk());
    bb = Buffer();
    bb.append("0123");
    bb.append("45".representation);
    bb.popFront();
    bb.popBack();
    assert(bb.front == '1');
    assert(bb[0] == '1');
    assert(bb.back == '4');
    assert(bb[$-1] == '4');
    assert(bb.data == "1234");
    assert(bb.length == 4);
    bb.popFront();
    bb.popBack();
    assert(bb.front == '2');
    assert(bb.back == '3');
    assert(bb.data == "23");
    assert(bb.length == 2);
    bb.popFront();
    bb.popBack();
    assert(bb.length == 0);

    bb = Buffer();
    bb.append("0123");
    bb.append("45");
    bb.popBack();
    bb.append("abc");
    assert(bb.back == 'c');
    assert(bb.length == 8);
    assert(bb == "01234abc");
    bb = Buffer();
    bb.append("0123");
    bb.append("4");
    bb.popBack();
    bb.append("abc");
    assert(bb.back == 'c');
    assert(bb.length == 7);
    assert(bb == "0123abc");
    bb = Buffer();
    bb.append("0123");
    bb.append("");
    bb.popBack();
    bb.append("abc");
    assert(bb.back == 'c');
    assert(bb.length == 6);
    assert(bb == "012abc");

    bb = Buffer();
    bb.append("0123".representation);
    bb.popFront();
    bb.popBack();
    assert(bb.front == '1');
    assert(bb.back == '2');
    assert(bb.length == 2);
    assert(equal(bb, "12"));
    assert(!bb.canFind('0'));
    assert(equal(bb.find('0'), ""));    // internal, fast
    assert(!bb.canFind('0'));
    assert(equal(bb.find('0'), ""));    // internal, fast
    assert(bb.canFind('1'));
    assert(equal(bb.find('1'), "12"));    // internal, fast
    assert(!bb.canFind('3'));
    assert(equal(find(bb, '3'), ""));   // use InputRange, slow

    bb.append("3");
    assert(bb.back == '3');
    assert(bb.length == 3);
    assert(equal(bb, "123"));
    assert(bb[0..$] == "123");
    assert(bb[$-1] == '3');
    assert(equal(bb.find('0'), ""));    // internal, fast
    assert(!bb.canFind('0'));
    assert(equal(bb.find('1'), "123"));    // internal, fast
    assert(bb.canFind('3'));
    assert(equal(bb.find('3'), "3"));  // internal method, fast
    assert(equal(find(bb, '3'), "3")); // use InputRange, slow

    bb = Buffer();
    bb.append("0");
    bb.append("1");
    bb.append("2");
    bb.append("3");
    assert(equal(bb.retro, "3210"));

    bb.popFront();
    bb.popBack();
    assert(bb.front == '1');
    assert(bb.back == '2');
    assert(bb.length == 2);
    assert(equal(bb, "12"));
    assert(!bb.canFind('0'));
    assert(equal(bb.find('0'), ""));    // internal, fast
    assert(!bb.canFind('0'));
    assert(equal(bb.find('0'), ""));    // internal, fast
    assert(bb.canFind('1'));
    assert(equal(bb.find('1'), "12"));    // internal, fast
    assert(!bb.canFind('3'));
    assert(equal(find(bb, '3'), ""));   // use InputRange, slow

    bb.append("3");
    assert(bb.back == '3');
    assert(bb.length == 3);
    assert(equal(bb, "123"));
    assert(bb[0..$] == "123");
    assert(bb[$-1] == '3');
    assert(equal(bb.find('0'), ""));    // internal, fast
    assert(!bb.canFind('0'));
    assert(equal(bb.find('1'), "123"));    // internal, fast
    assert(bb.canFind('3'));
    assert(equal(bb.find('3'), "3"));  // internal method, fast
    assert(equal(find(bb, '3'), "3")); // use InputRange, slow

    bb = Buffer();
    bb.append("aaa\n");
    bb.append("bbb\n");
    bb.append("ccc\n");
    assert(equal(splitter(bb, '\n').array[0], "aaa"));
    bb = Buffer();
    bb.append("0\naaa\n");
    bb.append("bbb\n");
    bb.popFront;
    bb.popFront;
    assert(equal(splitter(bb, '\n').array[0], "aaa"));
}

class DecodingException: Exception {
    this(string message, string file =__FILE__, size_t line = __LINE__, Throwable next = null) @safe pure nothrow {
        super(message, file, line, next);
    }
}
