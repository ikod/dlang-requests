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
        HTTPRequest   _http;  // route all http/https requests here
        FTPRequest    _ftp;   // route all ftp requests here
    }
    /// Set timeout on connection and IO operation.
    /// $(B v) - timeout value
    /// If timeout expired Request operation will throw $(B TimeoutException).
    @property void timeout(Duration v) pure @nogc nothrow {
        _http.timeout = v;
        _ftp.timeout = v;
    }
    /// Set http keepAlive value
    /// $(B v) - use keepalive requests - $(B true), or not - $(B false)
    /// Request will automatically reopen connection when host, protocol
    /// or port change (so it is safe to send different requests through
    /// single instance of Request).
    /// It also recovers if server prematurely close keep-alive connection.
    @property void keepAlive(bool v) pure @nogc nothrow {
        _keepAlive = v;
    }
    @property bool keepAlive() pure @nogc nothrow {
        return _keepAlive;
    }
    /// Set limit on HTTP redirects
    /// $(B v) - limit on redirect depth
    /// Throws $(B MaxRedirectsException) when limit is reached.
    @property void maxRedirects(uint v) pure @nogc nothrow {
        _maxRedirects = v;
    }
    @property auto maxRedirects() pure @nogc nothrow {
        return _maxRedirects;
    }
    /// Set maximum content lenth both for http and ftp requests
    /// $(B v) - maximum content length in bytes. When limit reached - throws $(B RequestException)
    @property void maxContentLength(size_t v) pure @nogc nothrow {
        _maxContentLength = v;
        //_http.maxContentLength = v;
        //_ftp.maxContentLength = v;
    }
    @property auto maxContentLength() pure @nogc nothrow {
        return _maxContentLength;
        //_http.maxContentLength = v;
        //_ftp.maxContentLength = v;
    }
    /// Set maximum length for HTTP headers
    /// $(B v) - maximum length of the HTTP response. When limit reached - throws $(B RequestException)
    @property void maxHeadersLength(size_t v) pure @nogc nothrow {
        _maxHeadersLength = v;
    }
    @property auto maxHeadersLength() pure @nogc nothrow {
        return _maxHeadersLength;
    }
    /// Set IO buffer size for http and ftp requests
    /// $(B v) - buffer size in bytes.
    @property void bufferSize(size_t v) {
        _http.bufferSize = v;
        _ftp.bufferSize = v;
    }
    /// Set verbosity for HTTP or FTP requests.
    /// $(B v) - verbosity level (0 - no output, 1 - headers to stdout, 2 - headers and data hexdump to stdout). default = 0.
    @property void verbosity(uint v) {
        _verbosity = v;
        _http.verbosity = v;
        _ftp.verbosity = v;
    }
    @property auto verbosity() {
        return _verbosity;
    }
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
    @property void authenticator(Auth v) {
        _authenticator = v;
        _http.authenticator = v;
        _ftp.authenticator = v;
    }
    @property auto authenticator() {
        return _authenticator;
    }
    /// set proxy property.
    /// $(B v) - full url to proxy.
    ///
    /// Note that we recognize proxy settings from process environment (see $(LINK https://github.com/ikod/dlang-requests/issues/46)):
    /// you can use http_proxy, https_proxy, all_proxy (as well as uppercase names).
    @property void proxy(string v) {
        _http.proxy = v;
        _ftp.proxy = v;
    }
    @property void socketFactory(NetworkStream delegate(string, string, ushort) f) {
        _http.socketFactory = f;
    }
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

    @property void useStreaming(bool v) pure @nogc nothrow {
        _useStreaming = v;
    }
    @property bool useStreaming() pure @nogc nothrow {
        return _useStreaming;
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
    //Response get(A...)(string uri, A args) {
    //    if ( uri ) {
    //        _uri = URI(uri);
    //        _uri.idn_encode();
    //    }
    //    _method = "GET";
    //    final switch ( _uri.scheme ) {
    //        case "http", "https":
    //            _http.uri = _uri;
    //            static if (__traits(compiles, _http.get(null, args))) {
    //                return _http.get(null, args);
    //            } else {
    //                throw new Exception("Operation not supported for http");
    //            }
    //        case "ftp":
    //            static if (args.length == 0) {
    //                return _ftp.get(uri);
    //            } else {
    //                throw new Exception("Operation not supported for ftp");
    //            }
    //    }
    //}
    /// Execute POST for http and STOR file for FTP.
    /// You have to provide  $(B uri) and data. Data should conform to HTTPRequest.post or FTPRequest.post depending on the URI scheme.
    /// When arguments do not conform scheme you will receive Exception("Operation not supported for ftp")
    ///
    //Response post(A...)(string uri, A args) {
    //    if ( uri ) {
    //        _uri = URI(uri);
    //        _uri.idn_encode();
    //    }
    //    _method = "POST";
    //    final switch ( _uri.scheme ) {
    //        case "http", "https":
    //            _http.uri = _uri;
    //            static if (__traits(compiles, _http.post(null, args))) {
    //                return _http.post(null, args);
    //            } else {
    //                throw new Exception("Operation not supported for http");
    //            }
    //        case "ftp":
    //            static if (__traits(compiles, _ftp.post(uri, args))) {
    //                return _ftp.post(uri, args);
    //            } else {
    //                throw new Exception("Operation not supported for ftp");
    //            }
    //    }
    //}
    /++
     + Execute request with method
     +/
    //Response exec(string method="GET", A...)(string uri, A args) {
    //    _method = method;
    //    _uri = URI(uri);
    //    _uri.idn_encode();
    //    _http.uri = _uri;
    //    return _http.exec!(method)(null, args);
    //}
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
    private QueryParam[]           _params;
    private MultipartForm          _multipartForm;
    private RefCounted!ConnManager _cm;                              // connection manager
    private string[URI]            _permanent_redirects;             // cache 301 redirects for GET requests
    private Interceptor[]          _interceptors;
    private string                 _contentType;                     // content type for POST/PUT payloads
    private InputRangeAdapter      _postData;

    @property auto cm() {
        return _cm;
    }
    @property string method() {
        return _method;
    }
    @property URI uri() {
        return _uri;
    }
    @property QueryParam[] params() {
        return _params;
    }
    @property string contentType()
    {
        return _contentType;
    }
    @property void contentType(string v)
    {
        _contentType = v;
    }
    @property InputRangeAdapter postData()
    {
        return _postData;
    }
    @property auto permanent_redirects() {
        return _permanent_redirects;
    }
    @property auto multipartForm()
    {
        return _multipartForm;
    }
    @property auto multipartForm(MultipartForm f)
    {
        return _multipartForm;
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
    class LogInterceptor : Interceptor {
        Response opCall(Request r, RequestHandler next)
        {
            info("interceptor enter");
            auto rs = next.handle(r);
            info("interceptor leaved, rs = %s".format(rs));
            return rs;
        }
    }
    globalLogLevel = LogLevel.trace;
    Request rq;
    Response rs;
    rq._cm = RefCounted!ConnManager(10);
    rq.addInterceptor(new LogInterceptor());

    infof("cm: %d", rq._cm.refCountedStore().refCount());
    rs = rq.execute("GET", "http://google.com");
    info("try streaming");
    rq.useStreaming = true;
    rq.bufferSize = 128;
    rs = rq.execute("GET", "http://google.com");
    auto s = rs.receiveAsRange;
    while (!s.empty)
    {
        s.front;
        s.popFront();
    }
    globalLogLevel = LogLevel.info;
}
