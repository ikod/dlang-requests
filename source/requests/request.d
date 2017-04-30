module requests.request;
import requests.http;
import requests.ftp;
import requests.streams;
import requests.base;
import requests.uri;

import std.datetime;
import std.conv;
import std.experimental.logger;
import std.format;
import requests.utils;


/**
   This is simplest interface to both http and ftp protocols.
   Request has methods get, post and exec which routed to proper concrete handler (http or ftp, etc).
   To enable some protocol-specific featutes you have to use protocol interface directly (see docs for HTTPRequest or FTPRequest)
*/
public struct Request {
    private {
        URI         _uri;
        HTTPRequest _http;  // route all http/https requests here
        FTPRequest  _ftp;   // route all ftp requests here
        string      _method;
    }
    /// Set timeout on IO operation.
    /// $(B v) - timeout value
    /// 
    @property void timeout(Duration v) pure @nogc nothrow {
        _http.timeout = v;
        _ftp.timeout = v;
    }
    /// Set http keepAlive value
    /// $(B v) - use keepalive requests - $(B true), or not - $(B false)
    @property void keepAlive(bool v) pure @nogc nothrow {
        _http.keepAlive = v;
    }
    /// Set limit on HTTP redirects
    /// $(B v) - limit on redirect depth
    @property void maxRedirects(uint v) pure @nogc nothrow {
        _http.maxRedirects = v;
    }
    /// Set maximum content lenth both for http and ftp requests
    /// $(B v) - maximum content length in bytes. When limit reached - throw RequestException
    @property void maxContentLength(size_t v) pure @nogc nothrow {
        _http.maxContentLength = v;
        _ftp.maxContentLength = v;
    }
    /// Set maximum length for HTTP headers
    /// $(B v) - maximum length of the HTTP response. When limit reached - throw RequestException
    @property void maxHeadersLength(size_t v) pure @nogc nothrow {
        _http.maxHeadersLength = v;
    }
    /// Set IO buffer size for http and ftp requests
    /// $(B v) - buffer size in bytes.
    @property void bufferSize(size_t v) {
        _http.bufferSize = v;
        _ftp.bufferSize = v;
    }
    /// Set verbosity for HTTP or FTP requests.
    /// $(B v) - verbosity level (0 - no output, 1 - headers to stdout, 2 - headers and body progress to stdout). default = 0.
    @property void verbosity(uint v) {
        _http.verbosity = v;
        _ftp.verbosity = v;
    }
    /// Set authenticator for http requests.
    /// $(B v) - Auth instance.
    @property void authenticator(Auth v) {
        _http.authenticator = v;
        _ftp.authenticator = v;
    }
    /// set proxy property.
    /// $(B v) - full url to proxy.
    @property void proxy(string v) {
        _http.proxy = v;
        _ftp.proxy = v;
    }
    /// Set Cookie for http requests.
    /// $(B v) - array of cookie.
    @property void cookie(Cookie[] v) pure @nogc nothrow {
        _http.cookie = v;
    }
    /// Get Cookie for http requests.
    /// $(B v) - array of cookie.
    @property Cookie[] cookie()  pure @nogc nothrow {
        return _http.cookie;
    }
    ///
    /// set "streaming" property
    /// Params:
    /// v = value to set (true - use streaming)
    /// 
    @property void useStreaming(bool v) pure @nogc nothrow {
        _http.useStreaming = v;
        _ftp.useStreaming = v;
    }
    ///
    /// get length og actually received content.
    /// this value increase over time, while we receive data
    /// 
    @property long contentReceived() pure @nogc nothrow {
        final switch ( _uri.scheme ) {
            case "http", "https":
                return _http.contentReceived;
            case "ftp":
                return _ftp.contentReceived;
        }
    }
    /// get contentLength of the responce
    @property long contentLength() pure @nogc nothrow {
        final switch ( _uri.scheme ) {
            case "http", "https":
                return _http.contentLength;
            case "ftp":
                return _ftp.contentLength;
        }
    }
    @property void sslSetVerifyPeer(bool v) {
        _http.sslSetVerifyPeer(v);
    }
    @property void sslSetKeyFile(string path, SSLOptions.filetype type = SSLOptions.filetype.pem) pure @safe nothrow @nogc {
        _http.sslSetKeyFile(path, type);
    }
    @property void sslSetCertFile(string path, SSLOptions.filetype type = SSLOptions.filetype.pem) pure @safe nothrow @nogc {
        _http.sslSetCertFile(path, type);
    }
    @property void sslSetCaCert(string path) pure @safe nothrow @nogc {
        _http.sslSetCaCert(path);
    }
    @property auto sslOptions() {
        return _http.sslOptions();
    }
    /// Add headers to request
    /// Params:
    /// headers = headers to send.
    void addHeaders(in string[string] headers) {
        _http.addHeaders(headers);
    }
    void clearHeaders() {
        _http.clearHeaders();
    }
    Response execute(A...)(string method, string uri, A args) {
        if ( uri ) {
            _uri = URI(uri);
        }
        final switch ( _uri.scheme ) {
            case "http", "https":
                return _http.execute!A(method, uri, args);
            case "ftp":
                if (method == "GET") {
                    return _ftp.get(uri);
                }
                if (method == "POST") {
                    static if (__traits(compiles, _ftp.post(uri, args))) {
                        return _ftp.post(uri, args);
                    } else {
                        throw new Exception("Operation not supported for ftp");
                    }
                }
                // for fto only GET and POST methods
                assert(0);
        }
    }
    /// Execute GET for http and retrieve file for FTP.
    /// You have to provide at least $(B uri). All other arguments should conform to HTTPRequest.get or FTPRequest.get depending on the URI scheme.
    /// When arguments do not conform scheme (for example you try to call get("ftp://somehost.net/pub/README", {"a":"b"}) which doesn't make sense)
    /// you will receive Exception("Operation not supported for ftp")
    ///
    Response get(A...)(string uri, A args) {
        if ( uri ) {
            _uri = URI(uri);
        }
        _method = "GET";
        final switch ( _uri.scheme ) {
            case "http", "https":
                _http.uri = _uri;
                static if (__traits(compiles, _http.get(null, args))) {
                    return _http.get(null, args);
                } else {
                    throw new Exception("Operation not supported for http");
                }
            case "ftp":
                static if (args.length == 0) {
                    return _ftp.get(uri);
                } else {
                    throw new Exception("Operation not supported for ftp");
                }
        }
    }
    /// Execute POST for http and STOR file for FTP.
    /// You have to provide  $(B uri) and data. Data should conform to HTTPRequest.post or FTPRequest.post depending on the URI scheme.
    /// When arguments do not conform scheme you will receive Exception("Operation not supported for ftp")
    ///
    Response post(A...)(string uri, A args) {
        if ( uri ) {
            _uri = URI(uri);
        }
        _method = "POST";
        final switch ( _uri.scheme ) {
            case "http", "https":
                _http.uri = _uri;
                static if (__traits(compiles, _http.post(null, args))) {
                    return _http.post(null, args);
                } else {
                    throw new Exception("Operation not supported for http");
                }
            case "ftp":
                static if (__traits(compiles, _ftp.post(uri, args))) {
                    return _ftp.post(uri, args);
                } else {
                    throw new Exception("Operation not supported for ftp");
                }
        }
    }
    /// Execute PUT for http and STOR file for FTP.
    /// You have to provide  $(B uri) and data. Data should conform to HTTPRequest.putt or FTPRequest.post depending on the URI scheme.
    /// When arguments do not conform scheme you will receive Exception("Operation not supported for ftp")
    ///
    Response put(A...)(string uri, A args) {
        if ( uri ) {
            _uri = URI(uri);
        }
        _method = "PUT";
        final switch ( _uri.scheme ) {
            case "http", "https":
                _http.uri = _uri;
                static if (__traits(compiles, _http.post(null, args))) {
                    return _http.exec!"PUT"(null, args);
                } else {
                    throw new Exception("Operation not supported for http");
                }
            case "ftp":
                static if (__traits(compiles, _ftp.post(uri, args))) {
                    return _ftp.post(uri, args);
                } else {
                    throw new Exception("Operation not supported for ftp");
                }
        }
    }
    /// Execute DELETE for http and DEL file for FTP(not implemented right now).
    ///
    Response del(A...)(string uri, A args) {
        if ( uri ) {
            _uri = URI(uri);
        }
        _method = "DELETE";
        final switch ( _uri.scheme ) {
            case "http", "https":
                _http.uri = _uri;
                static if (__traits(compiles, _http.post(null, args))) {
                    return _http.exec!"DELETE"(null, args);
                } else {
                    throw new Exception("Operation not supported for http");
                }
            case "ftp":
                static if (__traits(compiles, _ftp.post(uri, args))) {
                    return _ftp.del(uri, args);
                } else {
                    throw new Exception("Operation not supported for ftp");
                }
        }
    }
    Response exec(string method="GET", A...)(string uri, A args) {
        _method = method;
        _uri = URI(uri);
        _http.uri = _uri;
        return _http.exec!(method)(null, args);
    }

    string toString() const {
        return "Request(%s, %s)".format(_method, _uri.uri());
    }
    string format(string fmt) const {
        final switch(_uri.scheme) {
            case "http", "https":
                return _http.format(fmt);
            case "ftp":
                return _ftp.format(fmt);
        }
    }
}
