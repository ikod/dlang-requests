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
        URI           _uri;
        string        _method;
        bool          _useStreaming;
        uint          _maxRedirects = 10;
        Auth          _authenticator;
        size_t         _maxHeadersLength = 32 * 1024;   // 32 KB
        size_t         _maxContentLength;               // 0 - Unlimited
        uint           _verbosity = 0;
        bool          _keepAlive;
        size_t        _bufferSize = 16*1024;
        string        _proxy;
        NetStreamFactory       _socketFactory;
        QueryParam[]           _params;
        MultipartForm          _multipartForm;
        RefCounted!ConnManager _cm;                              // connection manager
        string[URI]            _permanent_redirects;             // cache 301 redirects for GET requests
        Interceptor[]          _interceptors;
        string                 _contentType;                     // content type for POST/PUT payloads
        InputRangeAdapter      _postData;
        Duration               _timeout = 30.seconds;

        HTTPRequest   _http;  // route all http/https requests here
        FTPRequest    _ftp;   // route all ftp requests here
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
    mixin(Getter_Setter!string("method"));
    mixin(Getter_Setter!URI("uri"));
    mixin(Getter_Setter!(QueryParam[])("params"));
    mixin(Getter_Setter!string("contentType"));
    mixin(Getter_Setter!InputRangeAdapter("postData"));
    mixin(Getter_Setter!(string[URI])("permanent_redirects"));
    mixin(Getter_Setter!MultipartForm("multipartForm"));
    mixin(Getter_Setter!NetStreamFactory("socketFactory"));
    mixin(Getter_Setter!bool("useStreaming"));
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
    @property void cookie(Cookie[] v) pure @nogc nothrow {
        _http.cookie = v;
    }
    /// Get Cookie for http requests.
    @property Cookie[] cookie()  pure @nogc nothrow {
        return _http.cookie;
    }
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
    @property void sslSetVerifyPeer(bool v) {
        _http.sslSetVerifyPeer(v);
    }

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
    @property void sslSetKeyFile(string path, SSLOptions.filetype type = SSLOptions.filetype.pem) pure @safe nothrow @nogc {
        _http.sslSetKeyFile(path, type);
    }

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
    @property void sslSetCertFile(string path, SSLOptions.filetype type = SSLOptions.filetype.pem) pure @safe nothrow @nogc {
        _http.sslSetCertFile(path, type);
    }

    /++
     + Set path to ssl ca cert file.
     + Example:
     + ---
     +     auto rq = Request();
     +     rq.sslSetCaCert("/opt/local/etc/openssl/cert.pem");
     +     auto rs = rq.get("https://localhost:4443/");
     + ---
     +/
    @property void sslSetCaCert(string path) pure @safe nothrow @nogc {
        _http.sslSetCaCert(path);
    }

    @property auto sslOptions() {
        return _http.sslOptions();
    }

    /++
     + Set local address for any outgoing requests.
     + $(B v) can be string with hostname or ip address.
     +/
    @property void bind(string v) {
        _http.bind(v);
        _ftp.bind(v);
    }

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
    void addHeaders(in string[string] headers) {
        _http.addHeaders(headers);
    }
    void clearHeaders() {
        _http.clearHeaders();
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
        final switch(_uri.scheme) {
            case "http", "https":
            return _http.format(fmt);
            case "ftp":
            return _ftp.format(fmt);
        }
    }

    /////////////////////////////////////////////////////////////////////

    @property auto cm() {
        return _cm;
    }
    @property bool hasMultipartForm()
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
            if ( r._uri.scheme == "ftp" )
            {
                FTPRequest ftp;
                return ftp.execute(r);
            }
            else
            {
                HTTPRequest http;
                return http.execute(r);
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
        if ( uri ) {
            _uri = URI(uri);
            _uri.idn_encode();
        }
        final switch ( _uri.scheme ) {
            case "http", "https":
                return execute("GET", uri, params);
            case "ftp":
                return execute("GET", uri);
        }
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
        auto interceptors = _interceptors ~ new LastInterceptor();
        auto handler = new RequestHandler(interceptors);
        return handler.handle(this);
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
