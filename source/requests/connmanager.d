module requests.connmanager;

import std.typecons;
import std.datetime;
import std.array;
import std.algorithm;
import std.exception;

import std.experimental.logger;

import requests.streams;

///
/// Keep opened connections for HTTP
/// it is cache over tuple(schema, host, port) -> connection
///
/// Evict least used
///
package class ConnManager {
    package alias  CMKey = Tuple!(string, string, ushort);
    package struct CMValue {
        NetworkStream   stream;
        SysTime         timestamp;
    }
    private {
        ubyte            _limit;
        CMValue[CMKey]   _cache;
    }
    this(ubyte limit = 10) {
        _limit = limit;
    }
    ~this() {
        enforce!Exception(_cache.length == 0, "You must clear connManager before it GC-ed");
    }
    ///
    /// evict oldest connection
    ///
    private CMKey evict()
    in { assert(_cache.length>0); }
    do {
        debug(requests) trace("looking something to evict");
        return _cache.byKeyValue().array.sort!"a.value.timestamp < b.value.timestamp".front().key;
    }
    ///
    /// put new stream in cache, evict old stream and return it
    /// If nothing evicted return null
    ///
    NetworkStream put(string schema, string host, ushort port, NetworkStream stream)
    in { assert(stream !is null);}
    out{ assert(_cache.length>0);}
    do {
        NetworkStream e;
        auto key = CMKey(schema, host, port);
        auto value_ptr = key in _cache;

        if ( value_ptr is null ) {
            CMValue v = {stream: stream, timestamp: Clock.currTime};
            if ( _cache.length >= _limit ) {
                CMKey k = evict();
                e = _cache[k].stream;
                _cache.remove(k);
            }
            _cache[key] = v;
            return e;
        }
        auto old_stream = (*value_ptr).stream;
        if (  old_stream != stream ) {
            debug(requests) trace("old stream != new stream");
            e = old_stream;
            (*value_ptr).stream = stream;
        }
        (*value_ptr).timestamp = Clock.currTime;
        return e;
    }

    NetworkStream get(string schema, string host, ushort port) {
        if ( auto value_ptr = CMKey(schema, host, port) in _cache ) {
            return (*value_ptr).stream;
        }
        return null;
    }

    NetworkStream del(string schema, string host, ushort port) {
        NetworkStream s;
        CMKey key = CMKey(schema, host, port);
        if ( auto value_ptr = key in _cache ) {
            s = (*value_ptr).stream;
        }
        _cache.remove(key);
        return s;
    }

    void clear()
    out { assert(_cache.length == 0); }
    do  {
        foreach(k,ref v; _cache) {
            debug(requests) tracef("Clear ConnManager entry %s", k);
            try {
                v.stream.close();
            } catch (Exception e) {
                debug(requests) tracef("%s while clear connmanager", e.msg);
            }
            _cache.remove(k);
        }
    }

}

unittest {
    globalLogLevel = LogLevel.trace;
    ConnManager cm = new ConnManager(2);
    auto s0 = new TCPStream();
    auto s1 = new TCPStream();
    auto s2 = new TCPStream();

    auto e = cm.put("http", "s0", 1, s0);
    assert(e is null);
    assert(cm.get("http", "s0", 1) == s0);

    e = cm.put("http", "s1", 1, s1);
    assert(e is null);
    assert(cm.get("http", "s1", 1) == s1);

    e = cm.put("http", "s2", 1, s2);
    assert(e !is null);
    assert(cm.get("http", "s2", 1) == s2);
    assert(e == s0); // oldest
    e.close();

    // at this moment we have s1, s2
    // let try to update s1
    auto s3 = new TCPStream;
    e = cm.put("http", "s1", 1, s3);
    assert(e == s1);
    e.close();
    assert(cm.get("http", "s1", 1) == s3);

    cm.clear();
    assert(cm.get("http", "s1", 1) is null);
}
