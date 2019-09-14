module requests.connmanager;

import std.typecons;
import std.datetime;
import std.array;
import std.algorithm;
import std.exception;
import std.format;

import std.experimental.logger;

import requests.streams;

import cachetools.cache;

/**
 * Keep opened connections for HTTP.
 * It is actually cache over tuple(schema, host, port) -> connection
 * with limited number of items.
 *
 * Evict least used.
*/

package struct ConnManager {
    package alias CMKey = Tuple!(string, string, ushort);
    package class CMValue {
        this(NetworkStream s) {
            stream = s;
        }
        NetworkStream stream;
        string toString() inout {
            return "%s".format(stream);
        }
    }
    private {
        CMValue[][CMKey]    map;
        int                 capacity;
        int                 counter;
    }
    this(int c) {
        capacity = c;
    }
    void clear()
    {
        foreach(v;map.byValue)
        {
            foreach(s; v) {
                s.stream.close();
            }
        }
        map.clear;
        counter = 0;
    }
    void put(string schema, string host, ushort port, NetworkStream stream) 
    in
    {
        assert(stream !is null);
        assert(stream.isConnected);
    }
    do
    {
        debug(requests) {
            tracef("Place connection to pool: %s://%s:%s", schema, host, port);
        }
        CMKey key = CMKey(schema, host, port);
        auto c = key in map;
        if ( c ) {
            (*c) ~= new CMValue(stream);
        } else {
            map[key] = [new CMValue(stream)];
        }
        counter++;
        if ( counter > capacity ) {
            auto k = map.byKey.front;
            debug(requests) {
                tracef("remove random key %s", k);
            }
            auto streams = map[k];
            auto s = streams[0].stream;
            counter--;
            map[k] = streams[1..$];
            if (map[k].length == 0) {
                map.remove(k);
            }
            s.close();
        }
    }

    NetworkStream get(string schema, string host, ushort port)
    do
    {
        CMKey key = CMKey(schema, host, port);
        auto c = key in map;
        if (c) {
            // trim and return last
            auto v = *c;
            auto s = v[$-1].stream;
            v = v[0..$-1];
            counter--;
            debug (requests) {
                tracef("Get connection from pool: %s://%s:%s - %s", schema, host, port, s);
            }
            if ( v.length == 0 ) {
                map.remove(key);
            }
            return s;
        }
        else {
            return null;
        }
    }

    // void del(string schema, string host, ushort port, NetworkStream str) 
    // {
    //     CMKey key = CMKey(schema, host, port);
    //     auto c = key in map;
    //     if ( c ) {
    //         immutable index = (*c).countUntil!(a => a.stream == str);
    //         if ( index > -1 ) {
    //             (*c).remove(index);
    //         }
    //     }
    // }
}

package struct ConnManager1 {
    package alias  CMKey = Tuple!(string, string, ushort);
    package class CMValue {
        NetworkStream   stream;
        bool            in_use;
        string toString() inout {
            return "%s:%s".format(in_use, stream);
        }
    }
    private {
        CacheLRU!(CMKey, CMValue[]) __cache;
    }
    this(int limit) {
        __cache = new CacheLRU!(CMKey, CMValue[]);
        __cache.size = limit;
        __cache.enableCacheEvents();
    }
    ~this() {
        clear();
    }
    @property auto length() {
        return __cache.length;
    }
    ///
    /// put new stream in cache, evict old stream and return it.
    /// If nothing evicted return null. Returned(evicted) connection can be
    /// closed.
    ///
    NetworkStream put(string schema, string host, ushort port, NetworkStream stream)
    in { assert(stream !is null);}
    out{ assert(__cache.length>0);}
    do {
        import std.stdio;
        CMKey     key = CMKey(schema, host, port);
        CMValue   new_value = new CMValue;
        new_value.stream = stream;
        new_value.in_use = true;

        CMValue[] old_values;
        auto cs = __cache.get(key);
        if ( !cs.isNull ) {
            old_values = cs.get();
        }
        __cache.put(key, old_values ~ new_value);

        writefln("new: %s", old_values ~ new_value);

        auto cacheEvents = __cache.cacheEvents();
        foreach(e; cacheEvents) {
            // if ( e.event == EventType.Evicted ) {

            // } else if (e.event == EventType.Updated) {

            // }
            //writeln(e);
        }
        return null;
        // switch( cacheEvents.length )
        // {
        //     case 0:
        //         return null;
        //     case 1:
        //         old_values = cacheEvents.front.val;
        //         foreach(s; old_values) {
        //             s.stream.close();
        //         }
        //         return null;
        //     default:
        //         assert(0);
        // }
    }
    /**
        Lookup connection.
     */
    NetworkStream get(string schema, string host, ushort port)
    do
    {
        if ( __cache is null ) return null;
        auto v = __cache.get(CMKey(schema, host, port));
        if ( ! v.isNull() )
        {
            auto streams = v.get;
            foreach(s; streams) {
                if ( !s.in_use ) {
                    s.in_use = true;
                    return s.stream;
                }
            }
        }
        return null;
    }

    /**
        Remove connection from cache (without close).
     */
    void del(string schema, string host, ushort port, NetworkStream str) {
        NetworkStream s;
        CMKey key = CMKey(schema, host, port);
        auto v = __cache.get(key);
        if ( v.isNull ) {
            return;
        }
        auto streams = v.get();
        int index;
        do {
            if ( streams[index].stream is str) {
                break;
            }
            index++;
        } while(index < streams.length);

        if ( index < streams.length ) {
            streams.remove(index);
        }

        if ( streams.length == 0 ) {
            __cache.remove(key);
        } else {
            __cache.put(key, streams);
        }
    }

    /**
        clear cache (and close connections)
     */
    void clear()
    out { assert(__cache is null || __cache.length == 0); }
    do  {
        if ( __cache is null ) return;

        __cache.clear();
        foreach(e; __cache.cacheEvents )
        {
            try
            {
                foreach(v; e.val) {
                    v.stream.close();
                }
            }
            catch(Exception e)
            {
                debug(requests) tracef("%s while clear connmanager", e.msg);
            }
        }
        __cache = null;
    }
}

// unittest {
//     globalLogLevel = LogLevel.info;
//     ConnManager cm = ConnManager(2);
//     auto s0 = new TCPStream();
//     auto s1 = new TCPStream();
//     auto s2 = new TCPStream();

//     auto e = cm.put("http", "s0", 1, s0);
//     assert(e is null);
//     assert(cm.get("http", "s0", 1) == s0);

//     e = cm.put("http", "s1", 1, s1);
//     assert(e is null);
//     assert(cm.get("http", "s1", 1) == s1);

//     e = cm.put("http", "s2", 1, s2);
// //    assert(e !is null);
//     assert(cm.get("http", "s2", 1) == s2);
// //    assert(e == s0); // oldest
// //    e.close();

//     // at this moment we have s1, s2
//     // let try to update s1
//     auto s3 = new TCPStream;
//     e = cm.put("http", "s1", 1, s3);
//     // assert(e == s1);
//     // e.close();
//     assert(cm.get("http", "s1", 1) == s3);

//     cm.clear();
//     assert(cm.get("http", "s1", 1) is null);
// }
