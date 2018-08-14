module requests.base;

import requests.streams;
import requests.utils;
import requests.uri;

import std.format;
import std.datetime;
import core.time;

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
    }
    ubyte[] front() {
        return data;
    }
    void popFront() {
        if ( read ) {
            // get new portion
            data = read();
        } else {
            // we can't read any new data
            data.length = 0;
        }
    }
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
        SysTime          _startedAt,
                         _connectedAt,
                         _requestSentAt,
                         _finishedAt;
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
    override string toString() const {
        return "Response(%d, %s)".format(_code, _uri.uri());
    }
    string format(string fmt) const {
        import std.array;
        auto a = appender!string();
        auto f = FormatSpec!char(fmt);
        while (f.writeUpToNextSpec(a)) {
            switch (f.spec) {
                case 'h':
                    // Remote hostname.
                    a.put(_uri.host);
                    break;
                case 'p':
                    // Remote port.
                    a.put("%d".format(_uri.port));
                    break;
                case 'P':
                    // Path.
                    a.put(_uri.path);
                    break;
                case 'q':
                    // query parameters supplied with url.
                    a.put(_uri.query);
                    break;
                case 's':
                    a.put("Response(%d, %s)".format(_code, _uri.uri()));
                    break;
                case 'B': // received bytes
                    a.put("%d".format(_responseBody.length));
                    break;
                case 'T': // request total time, ms
                    a.put("%d".format((_finishedAt - _startedAt).total!"msecs"));
                    break;
                case 'U':
                    a.put(_uri.uri());
                    break;
                case 'S':
                    a.put("%d".format(_code));
                    break;
                default:
                    throw new FormatException("Unknown Response format specifier: %" ~ f.spec);
            }
        }
        return a.data();
    }
}
