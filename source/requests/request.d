module requests.request;
import requests.http;
import requests.ftp;
import requests.streams;
import requests.base;
import requests.uri;

import std.datetime;
import std.conv;
import std.range;
import std.experimental.logger;
import std.format;
import std.typecons;
import std.stdio;
import std.algorithm;
import std.uni;

import requests.utils;
import requests.connmanager;
import requests.rangeadapter;

/**
   This is simplest interface to both http and ftp protocols.
   Request has methods get, post and exec which routed to proper concrete handler (http or ftp, etc).
   To enable some protocol-specific featutes you have to use protocol interface directly (see docs for HTTPRequest or FTPRequest)
*/

alias NetStreamFactory = NetworkStream delegate(string, string, ushort);

interface Interceptor {
    Response opCall(Request r, RequestHandler next);
}
class RequestHandler {
    private Interceptor[] _interceptors;
    this(Interceptor[] i)
    {
        _interceptors = i;
    }
    Response handle(Request r)
    {
        auto i = _interceptors.front();
        _interceptors.popFront();
        return i(r, this);
    }
}

public struct Request {
    private {
        // request configuration
        bool                    _useStreaming;
        uint                    _maxRedirects = 10;
        Auth                    _authenticator;
        size_t                  _maxHeadersLength = 32 * 1024;   // 32 KB
        size_t                  _maxContentLength;               // 0 - Unlimited
        uint                    _verbosity = 0;
        bool                    _keepAlive = true;
        size_t                  _bufferSize = 16*1024;
        string                  _proxy;
        string                  _contentType;                     // content type for POST/PUT payloads
        Duration                _timeout = 30.seconds;
        bool                    _sslSetVerifyPeer = true;
        SSLOptions              _sslOptions;
        string                  _bind;
        _UH                     _userHeaders;
        string[string]          _headers;
        //

        // instrumentation
        NetStreamFactory        _socketFactory;
        Interceptor[]           _interceptors;
        //

        // parameters for each request
        URI                     _uri;
        string                  _method;
        QueryParam[]            _params;
        MultipartForm           _multipartForm;
        InputRangeAdapter       _postData;
        //

        // can be changed during execution
        RefCounted!ConnManager  _cm;                              // connection manager
        RefCounted!Cookies      _cookie;                          // cookies received
        string[URI]             _permanent_redirects;             // cache 301 redirects for GET requests
        //

        //HTTPRequest   _http;  // route all http/https requests here
        //FTPRequest    _ftp;   // route all ftp requests here
    }
    /// Set timeout on connection and IO operation.
    /// $(B v) - timeout value
    /// If timeout expired Request operation will throw $(B TimeoutException).
    mixin(Getter_Setter!Duration("timeout"));
    /// Set http keepAlive value
    /// $(B v) - use keepalive requests - $(B true), or not - $(B false)
    /// Request will automatically reopen connection when host, protocol
    /// or port change (so it is safe to send different requests through
    /// single instance of Request).
    /// It also recovers if server prematurely close keep-alive connection.
    mixin(Getter_Setter!bool("keepAlive"));
    /// Set limit on HTTP redirects
    /// $(B v) - limit on redirect depth
    /// Throws $(B MaxRedirectsException) when limit is reached.
    mixin(Getter_Setter!uint("maxRedirects"));
    /// Set maximum content lenth both for http and ftp requests
    /// $(B v) - maximum content length in bytes. When limit reached - throws $(B RequestException)
    mixin(Getter_Setter!uint("maxContentLength"));
    /// Set maximum length for HTTP headers
    /// $(B v) - maximum length of the HTTP response. When limit reached - throws $(B RequestException)
    mixin(Getter_Setter!size_t("maxHeadersLength"));
    /// Set IO buffer size for http and ftp requests
    /// $(B v) - buffer size in bytes.
    mixin(Getter_Setter!size_t("bufferSize"));
    /// Set verbosity for HTTP or FTP requests.
    /// $(B v) - verbosity level (0 - no output, 1 - headers to stdout, 2 - headers and data hexdump to stdout). default = 0.
    mixin(Getter_Setter!uint("verbosity"));
    /++ Set authenticator for http requests.
     +   $(B v) - Auth instance.
     +   Example:
     +   ---
     +   import requests;
     +   void main() {
     +       rq = Request();
     +       rq.authenticator = new BasicAuthentication("user", "passwd");
     +       rs = rq.get("http://httpbin.org/basic-auth/user/passwd");
     +   }
     +   ---
     +/
    mixin(Getter_Setter!Auth("authenticator"));
    /// set proxy property.
    /// $(B v) - full url to proxy.
    ///
    /// Note that we recognize proxy settings from process environment (see $(LINK https://github.com/ikod/dlang-requests/issues/46)):
    /// you can use http_proxy, https_proxy, all_proxy (as well as uppercase names).
    mixin(Getter_Setter!string("proxy"));
    mixin(Getter("method"));
    mixin(Getter("uri"));
    mixin(Getter("params"));
    mixin(Getter("contentType"));
    mixin(Getter("postData"));
    mixin(Getter("permanent_redirects"));
    mixin(Getter("multipartForm"));
    mixin(Getter_Setter!NetStreamFactory("socketFactory"));
    mixin(Getter_Setter!bool("useStreaming"));
    mixin(Getter_Setter!(RefCounted!Cookies)("cookie"));
    mixin(Getter_Setter!string("bind"));
    mixin(Getter_Setter!(string[string])("headers"));

    mixin(Getter("sslOptions"));
    @property void sslSetVerifyPeer(bool v) pure @safe nothrow @nogc {
        _sslOptions.setVerifyPeer(v);
    }
    @property void sslSetKeyFile(string p, SSLOptions.filetype t = SSLOptions.filetype.pem) pure @safe nothrow @nogc {
        _sslOptions.setKeyFile(p, t);
    }
    @property void sslSetCertFile(string p, SSLOptions.filetype t = SSLOptions.filetype.pem) pure @safe nothrow @nogc {
        _sslOptions.setCertFile(p, t);
    }
    @property void sslSetCaCert(string path) pure @safe nothrow @nogc {
        _sslOptions.setCaCert(path);
    }

    package @property auto userHeaders() pure @safe nothrow @nogc
    {
        return _userHeaders;
    }

    //@property void socketFactory(NetworkStream delegate(string, string, ushort) f) {
    //    _http.socketFactory = f;
    //}
    /++ Set Cookie for http requests.
        $(B v) - array of cookie.

        You can set and read cookies. In the next example server set cookie and we read it.
        Example:
        ---
        void main() {
           rs = rq.get("http://httpbin.org/cookies/set?A=abcd&b=cdef");
           assert(rs.code == 200);
           auto json = parseJSON(cast(string)rs.responseBody.data).object["cookies"].object;
           assert(json["A"].str == "abcd");
           assert(json["b"].str == "cdef");
           foreach(c; rq.cookie) {
               final switch(c.attr) {
                   case "A":
                        assert(c.value == "abcd");
                        break;
                   case "b":
                        assert(c.value == "cdef");
                        break;
                }
            }
        }
        ---
    +/
    //@property void cookie(Cookie[] v) pure @nogc nothrow {
    //    _http.cookie = v;
    //}
    ///// Get Cookie for http requests.
    //@property Cookie[] cookie()  pure @nogc nothrow {
    //    return _http.cookie;
    //}
    /++
     set "streaming" property
     $(B v) = value to set (true - use streaming).

     Use streaming when you do not want to keep whole response in memory.
     Example:
     ---
     import requests;
     import std.stdio;

     void main() {
         Request rq = Request();

         rq.useStreaming = true;
         auto rs = rq.get("http://example.com/SomeHugePicture.png");
         auto stream = rs.receiveAsRange();
         File file = File("SomeHugePicture.png", "wb");

         while(!stream.empty)  {
             file.rawWrite(stream.front);
             stream.popFront;
         }
         file.close();
     }
     ---
    +/

    //@property void useStreaming(bool v) pure @nogc nothrow {
    //    _useStreaming = v;
    //}
    //@property bool useStreaming() pure @nogc nothrow {
    //    return _useStreaming;
    //}

    ///
    /// get length og actually received content.
    /// this value increase over time, while we receive data
    ///
    // XXX document relocation to response
    //@property long contentReceived() pure @nogc nothrow {
    //    final switch ( _uri.scheme ) {
    //        case "http", "https":
    //            return _http.contentReceived;
    //        case "ftp":
    //            return _ftp.contentReceived;
    //    }
    //}
    ///// get contentLength of the responce
    //@property long contentLength() pure @nogc nothrow {
    //    final switch ( _uri.scheme ) {
    //        case "http", "https":
    //            return _http.contentLength;
    //        case "ftp":
    //            return _ftp.contentLength;
    //    }
    //}
    /++
     + Enable or disable ssl peer verification.
     + $(B v) - enable if `true`, disable if `false`.
     +
     + Default - false.
     + Example:
     + ---
     +     auto rq = Request();
     +     rq.sslSetVerifyPeer(true);
     +     auto rs = rq.get("https://localhost:4443/");
     + ---
     +/
    //@property void sslSetVerifyPeer(bool v) {
    //    _http.sslSetVerifyPeer(v);
    //}

    /++
     + Set path to ssl key file.
     +
     + file type can be SSLOptions.filetype.pem (default) or SSLOptions.filetype.der or SSLOptions.filetype.asn1.
     +
     + if you configured only key file or only cert file, we will try to load counterpart from the same file.
     +
     + Example:
     + ---
     +     auto rq = Request();
     +     rq.sslSetKeyFile("client01.key");
     +     auto rs = rq.get("https://localhost:4443/");
     + ---
     +/
    /++
     + Set path to ssl cert file.
     +
     + file type can be SSLOptions.filetype.pem (default) or SSLOptions.filetype.der or SSLOptions.filetype.asn1.
     +
     + if you configured only key file or only cert file, we will try to load counterpart from the same file.
     +
     + Example:
     + ---
     +     auto rq = Request();
     +     rq.sslSetCertFile("client01.crt");
     +     auto rs = rq.get("https://localhost:4443/");
     + ---
     +/
    /++
     + Set path to ssl ca cert file.
     + Example:
     + ---
     +     auto rq = Request();
     +     rq.sslSetCaCert("/opt/local/etc/openssl/cert.pem");
     +     auto rs = rq.get("https://localhost:4443/");
     + ---
     +/
    /++
     + Set local address for any outgoing requests.
     + $(B v) can be string with hostname or ip address.
     +/
    //@property void bind(string v) {
    //    _http.bind(v);
    //    _ftp.bind(v);
    //}

    /++
     + Add headers to request
     + Params:
     + headers = headers to send.
     + Example:
     + ---
     +    rq = Request();
     +    rq.keepAlive = true;
     +    rq.addHeaders(["X-Header": "test"]);
     + ---
     +/
    /// Add headers to request
    /// Params:
    /// headers = headers to send.
    void addHeaders(in string[string] headers) {
        foreach(pair; headers.byKeyValue) {
            string _h = pair.key;
            switch(toLower(_h)) {
                case "host":
                    _userHeaders.Host = true;
                    break;
                case "user-agent":
                    _userHeaders.UserAgent = true;
                    break;
                case "content-length":
                    _userHeaders.ContentLength = true;
                    break;
                case "content-type":
                    _userHeaders.ContentType = true;
                    break;
                case "connection":
                    _userHeaders.Connection = true;
                    break;
                case "cookie":
                    _userHeaders.Cookie = true;
                    break;
                default:
                    break;
            }
            _headers[pair.key] = pair.value;
        }
    }
    void clearHeaders() {
        _headers = null;
        _userHeaders = _UH.init;
    }
    /// Execute GET for http and retrieve file for FTP.
    /// You have to provide at least $(B uri). All other arguments should conform to HTTPRequest.get or FTPRequest.get depending on the URI scheme.
    /// When arguments do not conform scheme (for example you try to call get("ftp://somehost.net/pub/README", {"a":"b"}) which doesn't make sense)
    /// you will receive Exception("Operation not supported for ftp")
    ///

    /// Execute POST for http and STOR file for FTP.
    /// You have to provide  $(B uri) and data. Data should conform to HTTPRequest.post or FTPRequest.post depending on the URI scheme.
    /// When arguments do not conform scheme you will receive Exception("Operation not supported for ftp")
    ///

    Response exec(string method="GET", A...)(string url, A args)
    {
        return execute(method, url, args);
    }
    string toString() const {
        return "Request(%s, %s)".format(_method, _uri.uri());
    }
    string format(string fmt) const {
        import std.array;
        import std.stdio;
        auto a = appender!string();
        auto f = FormatSpec!char(fmt);
        while (f.writeUpToNextSpec(a)) {
            switch(f.spec) {
                case 'h':
                // Remote hostname.
                a.put(_uri.host);
                break;
                case 'm':
                // method.
                a.put(_method);
                break;
                case 'p':
                // Remote port.
                a.put("%d".format(_uri.port));
                break;
                case 'P':
                // Path
                a.put(_uri.path);
                break;
                case 'q':
                // query parameters supplied with url.
                a.put(_uri.query);
                break;
                case 'U':
                a.put(_uri.uri());
                break;
                default:
                throw new FormatException("Unknown Request format spec " ~ f.spec);
            }
        }
        return a.data();
    }
    @property auto cm() {
        return _cm;
    }
    @property bool hasMultipartForm() const
    {
        return !_multipartForm.empty;
    }
    void addInterceptor(Interceptor i)
    {
        _interceptors ~= i;
    }
    class LastInterceptor : Interceptor
    {
        Response opCall(Request r, RequestHandler _)
        {
            switch (r._uri.scheme)
            {
                case "ftp":
                    FTPRequest ftp;
                    return ftp.execute(r);
                case "https","http":
                    HTTPRequest http;
                    return http.execute(r);
                default:
                    assert(0, "".format(r._uri.scheme));
            }
        }
    }
    Response post(string uri, string[string] query)
    {
        return execute("POST", uri, aa2params(query));
    }
    Response post(string uri, QueryParam[] query)
    {
        return execute("POST", uri, query);
    }
    Response post(string uri, MultipartForm form)
    {
        return execute("POST", uri, form);
    }
    Response post(R)(string uri, R content, string contentType="application/octet-stream")
    {
        return execute("POST", uri, content, contentType);
    }

    Response get(string uri, string[string] query)
    {
        return execute("GET", uri, aa2params(query));
    }
    Response get(string uri, QueryParam[] params = null)
    {
        return execute("GET", uri, params);
    }
    Response execute(R)(string method, string url, R content, string ct = "application/octet-stream")
    {
        _method = method;
        _uri = URI(url);
        _uri.idn_encode();
        _params = null;
        _multipartForm = MultipartForm.init;
        _contentType = ct;
        _postData = makeAdapter(content);
        // https://issues.dlang.org/show_bug.cgi?id=10535
        _permanent_redirects[URI.init] = ""; _permanent_redirects.remove(URI.init);
        //
        if ( _cm.refCountedStore().refCount() == 0)
        {
            _cm = RefCounted!ConnManager(10);
        }
        if ( _cookie.refCountedStore().refCount() == 0)
        {
            _cookie = RefCounted!Cookies();
        }
        auto interceptors = _interceptors ~ new LastInterceptor();
        auto handler = new RequestHandler(interceptors);
        return handler.handle(this);
        
    }
    Response execute(string method, string url, MultipartForm form)
    {
        _method = method;
        _uri = URI(url);
        _uri.idn_encode();
        _params = null;
        _multipartForm = form;

        // https://issues.dlang.org/show_bug.cgi?id=10535
        _permanent_redirects[URI.init] = ""; _permanent_redirects.remove(URI.init);
        //

        if ( _cm.refCountedStore().refCount() == 0)
        {
            _cm = RefCounted!ConnManager(10);
        }
        if ( _cookie.refCountedStore().refCount() == 0)
        {
            _cookie = RefCounted!Cookies();
        }
        auto interceptors = _interceptors ~ new LastInterceptor();
        auto handler = new RequestHandler(interceptors);
        return handler.handle(this);
    }
    Response execute(string method, string url, QueryParam[] params = null)
    {
        _method = method;
        _uri = URI(url);
        _uri.idn_encode();
        _multipartForm = MultipartForm.init;
        _params = params;

        // https://issues.dlang.org/show_bug.cgi?id=10535
        _permanent_redirects[URI.init] = ""; _permanent_redirects.remove(URI.init);
        //
        if ( _cm.refCountedStore().refCount() == 0)
        {
            _cm = RefCounted!ConnManager(10);
        }
        if ( _cookie.refCountedStore().refCount() == 0)
        {
            _cookie = RefCounted!Cookies(Cookies());
        }
        auto interceptors = _interceptors ~ new LastInterceptor();
        auto handler = new RequestHandler(interceptors);
        auto r = handler.handle(this);
        return r;
    }
    ///////////////////////////////////////////////////////////////////////
}

unittest {
    info("testing Request");
    int interceptorCalls;

    class DummyInterceptor : Interceptor {
        Response opCall(Request r, RequestHandler next)
        {
            interceptorCalls++;
            auto rs = next.handle(r);
            return rs;
        }
    }
    globalLogLevel = LogLevel.info;
    Request rq;
    Response rs;
    rq.addInterceptor(new DummyInterceptor());

    rs = rq.execute("GET", "http://google.com");
    rq.useStreaming = true;
    rq.bufferSize = 128;
    rs = rq.execute("GET", "http://google.com");
    auto s = rs.receiveAsRange;
    while (!s.empty)
    {
        s.front;
        s.popFront();
    }
    assert(interceptorCalls == 2, "Expected interceptorCalls==2, got %d".format(interceptorCalls));
    globalLogLevel = LogLevel.info;
}
