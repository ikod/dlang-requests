module requests;

public import requests.http;
public import requests.ftp;
public import requests.streams;
public import requests.base;
public import requests.uri;

import std.datetime;
import std.conv;
import std.experimental.logger;
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
    }
    /// Set timeout on IO operation.
    /// $(B v) - timeout value
    /// 
    public @property void timeout(Duration v) pure @nogc nothrow {
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
    /// Execute GET for http and retrieve file for FTP.
    /// You have to provide at least $(B uri). All other arguments should conform to HTTPRequest.get or FTPRequest.get depending on the URI scheme.
    /// When arguments do not conform scheme (for example you try to call get("ftp://somehost.net/pub/README", {"a":"b"}) which doesn't make sense)
    /// you will receive Exception("Operation not supported for ftp")
    ///
    Response get(A...)(string uri, A args) {
        if ( uri ) {
            _uri = URI(uri);
        }
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
    Response exec(string method="GET", A...)(A args) {
        return _http.exec!(method)(args);
    }
}
///
package unittest {
    import std.algorithm;
    import std.range;
    import std.array;
    import std.json;
    import std.stdio;
    import std.string;
    import std.exception;

    string httpbinUrl = httpTestServer();

    version(vibeD) {
    }
    else {
        import httpbin;
        auto server = httpbinApp();
        server.start();
        scope(exit) {
            server.stop();
        }
    }

    globalLogLevel(LogLevel.info);

    infof("testing Request");
    Request rq;
    Response rs;
    //
    rs = rq.get(httpbinUrl);
    assert(rs.code==200);
    assert(rs.responseBody.length > 0);
    rs = rq.get(httpbinUrl ~ "get", ["c":" d", "a":"b"]);
    assert(rs.code == 200);
    auto json = parseJSON(rs.responseBody.data).object["args"].object;
    assert(json["c"].str == " d");
    assert(json["a"].str == "b");
    
    rq = Request();
    rq.keepAlive = true;
    // handmade json
    info("Check POST json");
    rs = rq.post(httpbinUrl ~ "post?b=x", `{"a":"b ", "c":[1,2,3]}`, "application/json");
    assert(rs.code==200);
    json = parseJSON(rs.responseBody.data).object["args"].object;
    assert(json["b"].str == "x");
    json = parseJSON(rs.responseBody.data).object["json"].object;
    assert(json["a"].str == "b ");
    assert(json["c"].array.map!(a=>a.integer).array == [1,2,3]);
    {
        import std.file;
        import std.path;
        auto tmpd = tempDir();
        auto tmpfname = tmpd ~ dirSeparator ~ "request_test.txt";
        auto f = File(tmpfname, "wb");
        f.rawWrite("abcdefgh\n12345678\n");
        f.close();
        // files
        info("Check POST files");
        PostFile[] files = [
            {fileName: tmpfname, fieldName:"abc", contentType:"application/octet-stream"}, 
            {fileName: tmpfname}
        ];
        rs = rq.post(httpbinUrl ~ "post", files);
        assert(rs.code==200);
        info("Check POST chunked from file.byChunk");
        f = File(tmpfname, "rb");
        rs = rq.post(httpbinUrl ~ "post", f.byChunk(3), "application/octet-stream");
        assert(rs.code==200);
        auto data = fromJsonArrayToStr(parseJSON(rs.responseBody).object["data"]);
        assert(data=="abcdefgh\n12345678\n");
        f.close();
    }
    // ranges
    {
        info("Check POST chunked from lineSplitter");
        auto s = lineSplitter("one,\ntwo,\nthree.");
        rs = rq.exec!"POST"(httpbinUrl ~ "post", s, "application/octet-stream");
        assert(rs.code==200);
        auto data = fromJsonArrayToStr(parseJSON(rs.responseBody).object["data"]);
        assert(data=="one,two,three.");
    }
    {
        info("Check POST chunked from array");
        auto s = ["one,", "two,", "three."];
        rs = rq.post(httpbinUrl ~ "post", s, "application/octet-stream");
        assert(rs.code==200);
        auto data = fromJsonArrayToStr(parseJSON(rs.responseBody).object["data"]);
        assert(data=="one,two,three.");
    }
    {
        info("Check POST chunked using std.range.chunks()");
        auto s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        rs = rq.post(httpbinUrl ~ "post", s.representation.chunks(10), "application/octet-stream");
        assert(rs.code==200);
        auto data = fromJsonArrayToStr(parseJSON(rs.responseBody).object["data"]);
        assert(data==s);
    }
    // associative array
    rs = rq.post(httpbinUrl ~ "post", ["a":"b ", "c":"d"]);
    assert(rs.code==200);
    auto form = parseJSON(rs.responseBody.data).object["form"].object;
    assert(form["a"].str == "b ");
    assert(form["c"].str == "d");
    info("Check HEAD");
    rs = rq.exec!"HEAD"(httpbinUrl);
    assert(rs.code==200);
    info("Check DELETE");
    rs = rq.exec!"DELETE"(httpbinUrl ~ "delete");
    assert(rs.code==200);
    info("Check PUT");
    rs = rq.exec!"PUT"(httpbinUrl ~ "put",  `{"a":"b", "c":[1,2,3]}`, "application/json");
    assert(rs.code==200);
    info("Check PATCH");
    rs = rq.exec!"PATCH"(httpbinUrl ~ "patch", "привiт, свiт!", "application/octet-stream");
    assert(rs.code==200);
    
    info("Check compressed content");
    rq = Request();
    rq.keepAlive = true;
    rq.addHeaders(["X-Header": "test"]);
    rs = rq.get(httpbinUrl ~ "gzip");
    assert(rs.code==200);
    info("gzip - ok");
    rs = rq.get(httpbinUrl ~ "deflate");
    assert(rs.code==200);
    info("deflate - ok");
    
    info("Check redirects");
    rq = Request();
    rq.keepAlive = true;
    rs = rq.get(httpbinUrl ~ "relative-redirect/2");
    assert((cast(HTTPResponse)rs).history.length == 2);
    assert((cast(HTTPResponse)rs).code==200);

    info("Check cookie");
    rq = Request();
    rs = rq.get(httpbinUrl ~ "cookies/set?A=abcd&b=cdef");
    assert(rs.code == 200);
    json = parseJSON(rs.responseBody.data).object["cookies"].object;
    assert(json["A"].str == "abcd");
    assert(json["b"].str == "cdef");
    auto cookie = rq.cookie();
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
    rs = rq.get(httpbinUrl ~ "absolute-redirect/2");
    assert((cast(HTTPResponse)rs).history.length == 2);
    assert((cast(HTTPResponse)rs).code==200);
    //    rq = Request();
    rq.maxRedirects = 2;
    rq.keepAlive = false;
    assertThrown!MaxRedirectsException(rq.get(httpbinUrl ~ "absolute-redirect/3"));

    info("Check chunked content");
    rq = Request();
    rq.keepAlive = true;
    rq.bufferSize = 16*1024;
    rs = rq.get(httpbinUrl ~ "range/1024");
    assert(rs.code==200);
    assert(rs.responseBody.length==1024);
    
    info("Check basic auth");
    rq = Request();
    rq.authenticator = new BasicAuthentication("user", "passwd");
    rs = rq.get(httpbinUrl ~ "basic-auth/user/passwd");
    assert(rs.code==200);
    
    info("Check limits");
    rq = Request();
    rq.maxContentLength = 1;
    assertThrown!RequestException(rq.get(httpbinUrl));
    rq = Request();
    rq.maxHeadersLength = 1;
    assertThrown!RequestException(rq.get(httpbinUrl));

    info("Test getContent");
    auto r = getContent(httpbinUrl ~ "stream/20");
    assert(r.splitter('\n').filter!("a.length>0").count == 20);
    r = getContent(httpbinUrl ~ "get", ["a":"b", "c":"d"]);
    string name = "user", sex = "male";
    int    age = 42;
    r = getContent(httpbinUrl ~ "get", "name", name, "age", age, "sex", sex);

    info("Test receiveAsRange with GET");
    rq = Request();
    rq.useStreaming = true;
    rq.bufferSize = 16;
    rs = rq.get(httpbinUrl ~ "stream/20");
    auto stream = rs.receiveAsRange();
    ubyte[] streamedContent;
    while( !stream.empty() ) {
        streamedContent ~= stream.front;
        stream.popFront();
    }
    rq = Request();
    rs = rq.get(httpbinUrl ~ "stream/20");
    assert(streamedContent == rs.responseBody.data);
    info("Test postContent");
    r = postContent(httpbinUrl ~ "post", `{"a":"b", "c":1}`, "application/json");
    assert(parseJSON(r).object["json"].object["c"].integer == 1);

    /// Posting to forms (for small data)
    ///
    /// posting query parameters using "application/x-www-form-urlencoded"
    info("Test postContent using query params");
    postContent(httpbinUrl ~ "post", queryParams("first", "a", "second", 2));
    
    /// posting using multipart/form-data (large data and files). See docs fot HTTPRequest
    info("Test postContent form");
    MultipartForm mpform;
    mpform.add(formData(/* field name */ "greeting", /* content */ cast(ubyte[])"hello"));
    postContent(httpbinUrl ~ "post", mpform);
    
    /// you can do this using Request struct to access response details
    info("Test postContent form via Request()");
    rq = Request();
    mpform = MultipartForm().add(formData(/* field name */ "greeting", /* content */ cast(ubyte[])"hello"));
    rs = rq.post(httpbinUrl ~ "post", mpform);
    assert(rs.code == 200);
    
    info("Test receiveAsRange with POST");
    streamedContent.length = 0;
    rq = Request();
    rq.useStreaming = true;
    rq.bufferSize = 16;
    string s = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    rs = rq.post(httpbinUrl ~ "post", s.representation.chunks(10), "application/octet-stream");
    stream = rs.receiveAsRange();
    while( !stream.empty() ) {
        streamedContent ~= stream.front;
        stream.popFront();
    }
    rq = Request();
    rs = rq.post(httpbinUrl ~ "post", s.representation.chunks(10), "application/octet-stream");
    assert(streamedContent == rs.responseBody.data);
    info("Test get in parallel");
    {
        import std.stdio;
        import std.parallelism;
        import std.algorithm;
        import std.string;
        import core.atomic;
        
        immutable auto urls = [
            "stream/10",
            "stream/20",
            "stream/30",
            "stream/40",
            "stream/50",
            "stream/60",
            "stream/70",
        ].map!(a => httpbinUrl ~ a).array.idup;
        
        defaultPoolThreads(4);
        
        shared short lines;
        
        foreach(url; parallel(urls)) {
            atomicOp!"+="(lines, getContent(url).splitter("\n").count);
        }
        assert(lines == 287);
        
    }
}

auto queryParams(A...)(A args) pure @safe nothrow {
    QueryParam[] res;
    static if ( args.length >= 2 ) {
        res = QueryParam(args[0].to!string, args[1].to!string) ~ queryParams(args[2..$]);
    }
    return res;
}
/**
 * Call GET, and return response content.
 * This is the simplest case, when all you need is the response body and have no parameters.
 * Returns:
 * Buffer!ubyte which you can use as ForwardRange or DirectAccessRange, or extract data with .data() method.
 */
public auto ref getContent(A...)(string url) {
    auto rq = Request();
    auto rs = rq.get(url);
    return rs.responseBody;
}
/**
 * Call GET, and return response content.
 * args = string[string] fo query parameters.
 * Returns:
 * Buffer!ubyte which you can use as ForwardRange or DirectAccessRange, or extract data with .data() method.
 */
public auto ref getContent(A...)(string url, string[string] args) {
    auto rq = Request();
    auto rs = rq.get(url, args);
    return rs.responseBody;
}
/**
 * Call GET, and return response content.
 * args = QueryParam[] of parameters.
 * Returns:
 * Buffer!ubyte which you can use as ForwardRange or DirectAccessRange, or extract data with .data() method.
 */
public auto ref getContent(A...)(string url, QueryParam[] args) {
    auto rq = Request();
    auto rs = rq.get(url, args);
    return rs.responseBody;
}
/**
 * Call GET, and return response content.
 * args = variadic args to supply parameter names and values.
 * Returns:
 * Buffer!ubyte which you can use as ForwardRange or DirectAccessRange, or extract data with .data() method.
 */
public auto ref getContent(A...)(string url, A args) if (args.length > 1 && args.length % 2 == 0 ) {
    return Request().
            get(url, queryParams(args)).
            responseBody;
}

///
/// Call post and return response content.
///
public auto postContent(A...)(string url, A args) {
    auto rq = Request();
    auto rs = rq.post(url, args);
    return rs.responseBody;
}

///
package unittest {
    import std.json;
    import std.string;
    import std.stdio;
    import std.range;

    globalLogLevel(LogLevel.info);

    /// ftp upload from range
    info("Test postContent ftp");
    auto r = postContent("ftp://speedtest.tele2.net/upload/TEST.TXT", "test, ignore please\n".representation);
    assert(r.length == 0);

    info("Test getContent(ftp)");
    r = getContent("ftp://speedtest.tele2.net/1KB.zip");
    assert(r.length == 1024);
    
    info("Test receiveAsRange with GET(ftp)");
    ubyte[] streamedContent;
    auto rq = Request();
    rq.useStreaming = true;
    streamedContent.length = 0;
    auto rs = rq.get("ftp://speedtest.tele2.net/1KB.zip");
    auto stream = rs.receiveAsRange;
    while( !stream.empty() ) {
        streamedContent ~= stream.front;
        stream.popFront();
    }
    assert(streamedContent.length == 1024);
    //
    info("ftp post ", "ftp://speedtest.tele2.net/upload/TEST.TXT");
    rs = rq.post("ftp://speedtest.tele2.net/upload/TEST.TXT", "test, ignore please\n".representation);
    assert(rs.code == 226);
    info("ftp get  ", "ftp://speedtest.tele2.net/nonexistent", ", in same session.");
    rs = rq.get("ftp://speedtest.tele2.net/nonexistent");
    assert(rs.code != 226);
    rq.useStreaming = false;
    info("ftp get  ", "ftp://speedtest.tele2.net/1KB.zip", ", in same session.");
    rs = rq.get("ftp://speedtest.tele2.net/1KB.zip");
    assert(rs.code == 226);
    assert(rs.responseBody.length == 1024);
    info("ftp post ", "ftp://speedtest.tele2.net/upload/TEST.TXT");
    rs = rq.post("ftp://speedtest.tele2.net/upload/TEST.TXT", "another test, ignore please\n".representation);
    assert(rs.code == 226);
    info("ftp get  ", "ftp://ftp.iij.ad.jp/pub/FreeBSD/README.TXT");
    rs = rq.get("ftp://ftp.iij.ad.jp/pub/FreeBSD/README.TXT");
    assert(rs.code == 226);
    info("testing ftp - done.");
}

