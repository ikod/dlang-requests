module requests.rangeadapter;


/+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++/
/*                                                                       */
/* I need this module to unify input content for POST/PUT requests.      */
/* Input content must be converted to ubyte[] or ubyte[][].              */
/* In latter case it will be transferred in transfer-Encoding: chunked.  */
/* I need to erase type of input range and convert it to bytes, because  */
/* interceptors have no access to input range type.                      */
/*                                                                       */
/+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++/

import std.format;
import std.range.primitives;

private template rank(R) {
    static if ( isInputRange!R ) {
        enum size_t rank = 1 + rank!(ElementType!R);
    } else {
        enum size_t rank = 0;
    }
}

private struct Adapter(R) {
    R       _r;
    long    _length = -1;

    enum _rank = rank!R;
    static if ( _rank == 1 ){
        bool _empty = false;
    }
    this(R r)
    {
        _r = r;
        static if ( _rank == 1 && hasLength!R ) {
            _length = _r.length;
        }
    }
    immutable(ubyte)[] front()
    {
        static if ( _rank == 1 )
        {
            return cast(immutable(ubyte)[])_r[0..$];
        }
        static if ( _rank == 2 )
        {
            return cast(immutable(ubyte)[])_r.front;
        }
    }
    bool empty()
    {
        static if ( _rank == 1 )
        {
            return _empty;
        }
        static if ( _rank == 2 )
        {
            return _r.empty;
        }
    }
    void popFront()
    {
        static if ( _rank == 1 )
        {
            _empty = true;
        }
        static if ( _rank == 2 )
        {
            _r.popFront;
        }
    }
}

private auto ma(R)(R r) {
    return new Adapter!R(r);
}


package InputRangeAdapter makeAdapter(R)(R r) {
    auto adapter = ma(r);
    InputRangeAdapter result;
    result._front = &adapter.front;
    result._empty = &adapter.empty;
    result._popFront = &adapter.popFront;
    result._length = adapter._length;
    return result;
}

struct InputRangeAdapter {
    private {
        immutable(ubyte)[]  delegate() _front;
        bool                delegate() _empty;
        void                delegate() _popFront;
        long                           _length = -1;
    }
    immutable(ubyte)[] front() {
        return _front();
    }
    bool empty() const {
        if ( _empty is null )
        {
            return true;
        }
        return _empty();
    }
    void popFront() {
        _popFront();
    }
    long length() const {
        return _length;
    }
}

unittest {
    import std.string;
    import std.algorithm.comparison;
    import std.stdio;

    auto s0 = "abc";
    InputRangeAdapter ira = makeAdapter(s0);
    assert(ira.equal(["abc"]));

    auto s1 = "abc".representation();
    ira = makeAdapter(s1);
    assert(ira.equal(["abc".representation()]));

    auto s2 = ["abc".representation, "кококо".representation];
    ira = makeAdapter(s2);
    assert(ira.equal(s2));

    auto f = File("README.md", "r");
    auto r = f.byLine();
    ira = makeAdapter(r);
}