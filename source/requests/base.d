module requests.base;

import requests.streams;
import requests.utils;
import requests.uri;

public class RequestException: Exception {
    this(string msg, string file = __FILE__, size_t line = __LINE__) @safe pure {
        super(msg, file, line);
    }
}

public struct ContentIterator {
    bool empty() {
        return data.length == 0;
    };
    ubyte[] front() {
        return data.data;
    };
    void popFront() {
        if ( read ) {
            // get new portion
            data = read();
        } else {
            // we can't read any new data
            data = Buffer!(ubyte).init;
        }
    };
    package {
        bool            activated;
        Buffer!ubyte    data;
        Buffer!ubyte    delegate() read;
        ubyte[]         b;
    }
}

public class Response {
    package {
        ushort           _code;
        Buffer!ubyte     _responseBody;
        /// Initial URI
        URI              _uri;
        /// Final URI. Can differ from __URI if request go through redirections.
        URI              _finalURI;
        ContentIterator  _contentIterator;
        mixin(Setter!ushort("code"));
        mixin(Setter!URI("uri"));
        mixin(Setter!URI("finalURI"));
    }
    mixin(Getter!ushort("code"));
    mixin(Getter!URI("uri"));
    mixin(Getter!URI("finalURI"));
    @property auto responseBody() pure @safe nothrow {
        return _responseBody;
    }
    @property auto ref contentIterator() pure @safe nothrow {
        return _contentIterator;
    }
}
