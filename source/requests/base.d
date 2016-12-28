module requests.base;

import requests.streams;
import requests.utils;
import requests.uri;

public interface Auth {
    string[string] authHeaders(string domain);
    string         userName();
    string         password();
}

public class RequestException: Exception {
    this(string msg, string file = __FILE__, size_t line = __LINE__, Throwable next = null) @safe pure nothrow {
        super(msg, file, line, next);
    }
}

public struct ReceiveAsRange {
    bool empty() {
        return data.length == 0;
    };
    ubyte[] front() {
        return data;
    };
    void popFront() {
        if ( read ) {
            // get new portion
            data = read();
        } else {
            // we can't read any new data
            data.length = 0;
        }
    };
    package {
        bool            activated;
        ubyte[]         data;
        ubyte[]         delegate() read;
    }
}

public class Response {
    package {
        ushort           _code;
        Buffer!ubyte     _responseBody;
        string[string]   _responseHeaders;
        /// Initial URI
        URI              _uri;
        /// Final URI. Can differ from __URI if request go through redirections.
        URI              _finalURI;
        ReceiveAsRange   _receiveAsRange;
        mixin(Setter!ushort("code"));
        mixin(Setter!URI("uri"));
        mixin(Setter!URI("finalURI"));
    }
    mixin(Getter!ushort("code"));
    mixin(Getter!URI("uri"));
    mixin(Getter!URI("finalURI"));
    @property auto ref responseBody() @safe nothrow {
        return _responseBody;
    }
    @property auto ref responseHeaders() pure @safe nothrow {
        return _responseHeaders;
    }
    @property auto ref receiveAsRange() pure @safe nothrow {
        return _receiveAsRange;
    }
}
