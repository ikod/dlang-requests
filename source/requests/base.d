module requests.base;

import requests.streams;
import requests.utils;
import requests.uri;

public class RequestException: Exception {
    this(string msg, string file = __FILE__, size_t line = __LINE__) @safe pure {
        super(msg, file, line);
    }
}

public class Response {
    package {
        ushort         __code;
        Buffer!ubyte   __responseBody;
        /// Initial URI
        URI            __URI;
        /// Final URI. Can differ from __URI if request go through redirections.
        URI            __finalURI;
        mixin(setter("code"));
        mixin(setter("URI"));
        mixin(setter("finalURI"));
    }
    mixin(getter("code"));
    mixin(getter("URI"));
    mixin(getter("finalURI"));
    @property auto responseBody() pure @safe nothrow {
        return __responseBody;
    }
}
