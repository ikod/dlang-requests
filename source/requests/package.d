module requests;

public import requests.http;
public import requests.ftp;
public import requests.streams;
public import requests.base;
public import requests.uri;

import std.datetime;
import std.conv;
import std.experimental.logger;
import requests.uri;

/***********************************
 * This is simplest interface to both http and ftp protocols.
 * Request has methods get, post and exec which routed to proper concrete handler (http or ftp, etc).
 * To enable some protocol-specific featutes you have to use protocol interface directly (see docs for HTTPRequest or FTPRequest)
 */
struct Request {
    private {
        URI         _uri;
        HTTPRequest _http;  // route all http/https requests here
        FTPRequest  _ftp;   // route all ftp requests here
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
    @property void useStreaming(bool v) pure @nogc nothrow {
        _http.useStreaming = v;
        _ftp.useStreaming = v;
    }
    @property long contentReceived() pure @nogc nothrow {
        final switch ( _uri.scheme ) {
            case "http", "https":
                return _http.contentReceived;
            case "ftp":
                return _ftp.contentReceived;
        }
    }
    @property long contentLength() pure @nogc nothrow {
        final switch ( _uri.scheme ) {
            case "http", "https":
                return _http.contentLength;
            case "ftp":
                return _ftp.contentLength;
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

    globalLogLevel(LogLevel.info);

    infof("testing Request");
    Request rq;
    Response rs;
    //
    rs = rq.get("https://httpbin.org/");
    assert(rs.code==200);
    assert(rs.responseBody.length > 0);
    rs = rq.get("http://httpbin.org/get", ["c":" d", "a":"b"]);
    assert(rs.code == 200);
    auto json = parseJSON(rs.responseBody.data).object["args"].object;
    assert(json["c"].str == " d");
    assert(json["a"].str == "b");
    
    globalLogLevel(LogLevel.info);
    rq = Request();
    rq.keepAlive = true;
    // handmade json
    info("Check POST json");
    rs = rq.post("http://httpbin.org/post?b=x", `{"a":"☺ ", "c":[1,2,3]}`, "application/json");
    assert(rs.code==200);
    json = parseJSON(rs.responseBody.data).object["args"].object;
    assert(json["b"].str == "x");
    json = parseJSON(rs.responseBody.data).object["json"].object;
    assert(json["a"].str == "☺ ");
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
        globalLogLevel(LogLevel.info);
        info("Check POST files");
        PostFile[] files = [
        {fileName: tmpfname, fieldName:"abc", contentType:"application/octet-stream"}, 
        {fileName: tmpfname}
        ];
        rs = rq.post("http://httpbin.org/post", files);
        assert(rs.code==200);
        info("Check POST chunked from file.byChunk");
        f = File(tmpfname, "rb");
        rs = rq.post("http://httpbin.org/post", f.byChunk(3), "application/octet-stream");
        assert(rs.code==200);
        auto data = parseJSON(rs.responseBody.data).object["data"].str;
        assert(data=="abcdefgh\n12345678\n");
        f.close();
    }
    {
        // string
        info("Check POST utf8 string");
        rs = rq.post("http://httpbin.org/post", "привiт, свiт!", "application/octet-stream");
        assert(rs.code==200);
        auto data = parseJSON(rs.responseBody.data).object["data"].str;
        assert(data=="привiт, свiт!");
    }
    // ranges
    {
        info("Check POST chunked from lineSplitter");
        auto s = lineSplitter("one,\ntwo,\nthree.");
        rs = rq.exec!"POST"("http://httpbin.org/post", s, "application/octet-stream");
        assert(rs.code==200);
        auto data = parseJSON(rs.responseBody.toString).object["data"].str;
        assert(data=="one,two,three.");
    }
    {
        info("Check POST chunked from array");
        auto s = ["one,", "two,", "three."];
        rs = rq.post("http://httpbin.org/post", s, "application/octet-stream");
        assert(rs.code==200);
        auto data = parseJSON(rs.responseBody.data).object["data"].str;
        assert(data=="one,two,three.");
    }
    {
        info("Check POST chunked using std.range.chunks()");
        auto s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        rs = rq.post("http://httpbin.org/post", s.representation.chunks(10), "application/octet-stream");
        assert(rs.code==200);
        auto data = parseJSON(rs.responseBody.data).object["data"].str;
        assert(data==s);
    }
    // associative array
    rs = rq.post("http://httpbin.org/post", ["a":"b ", "c":"d"]);
    assert(rs.code==200);
    auto form = parseJSON(rs.responseBody.data).object["form"].object;
    assert(form["a"].str == "b ");
    assert(form["c"].str == "d");
    info("Check HEAD");
    rs = rq.exec!"HEAD"("http://httpbin.org/");
    assert(rs.code==200);
    info("Check DELETE");
    rs = rq.exec!"DELETE"("http://httpbin.org/delete");
    assert(rs.code==200);
    info("Check PUT");
    rs = rq.exec!"PUT"("http://httpbin.org/put",  `{"a":"b", "c":[1,2,3]}`, "application/json");
    assert(rs.code==200);
    info("Check PATCH");
    rs = rq.exec!"PATCH"("http://httpbin.org/patch", "привiт, свiт!", "application/octet-stream");
    assert(rs.code==200);
    
    info("Check compressed content");
    globalLogLevel(LogLevel.info);
    rq = Request();
    rq.keepAlive = true;
    rs = rq.get("http://httpbin.org/gzip");
    assert(rs.code==200);
    info("gzip - ok");
    rs = rq.get("http://httpbin.org/deflate");
    assert(rs.code==200);
    info("deflate - ok");
    
    info("Check redirects");
    globalLogLevel(LogLevel.info);
    rq = Request();
    rq.keepAlive = true;
    rs = rq.get("http://httpbin.org/relative-redirect/2");
    assert((cast(HTTPResponse)rs).history.length == 2);
    assert((cast(HTTPResponse)rs).code==200);

    info("Check cookie");
    rq = Request();
    rs = rq.get("http://httpbin.org/cookies/set?A=abcd&b=cdef");
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
    rs = rq.get("http://httpbin.org/absolute-redirect/2");
    assert((cast(HTTPResponse)rs).history.length == 2);
    assert((cast(HTTPResponse)rs).code==200);
    //    rq = Request();
    rq.maxRedirects = 2;
    rq.keepAlive = false;
    rs = rq.get("https://httpbin.org/absolute-redirect/3");
    assert((cast(HTTPResponse)rs).history.length == 2);
    assert((cast(HTTPResponse)rs).code==302);
    
    info("Check utf8 content");
    globalLogLevel(LogLevel.info);
    rq = Request();
    rs = rq.get("http://httpbin.org/encoding/utf8");
    assert(rs.code==200);
    
    info("Check chunked content");
    globalLogLevel(LogLevel.info);
    rq = Request();
    rq.keepAlive = true;
    rq.bufferSize = 16*1024;
    rs = rq.get("http://httpbin.org/range/1024");
    assert(rs.code==200);
    assert(rs.responseBody.length==1024);
    
    info("Check basic auth");
    globalLogLevel(LogLevel.info);
    rq = Request();
    rq.authenticator = new BasicAuthentication("user", "passwd");
    rs = rq.get("http://httpbin.org/basic-auth/user/passwd");
    assert(rs.code==200);
    
    globalLogLevel(LogLevel.info);
    info("Check limits");
    rq = Request();
    rq.maxContentLength = 1;
    assertThrown!RequestException(rq.get("http://httpbin.org/"));
    rq = Request();
    rq.maxHeadersLength = 1;
    assertThrown!RequestException(rq.get("http://httpbin.org/"));
    //
    info("ftp post ", "ftp://speedtest.tele2.net/upload/TEST.TXT");
    rs = rq.post("ftp://speedtest.tele2.net/upload/TEST.TXT", "test, ignore please\n".representation);
    assert(rs.code == 226);
    info("ftp get  ", "ftp://speedtest.tele2.net/nonexistent", ", in same session.");
    rs = rq.get("ftp://speedtest.tele2.net/nonexistent");
    assert(rs.code != 226);
    info("ftp get  ", "ftp://speedtest.tele2.net/1KB.zip", ", in same session.");
    rs = rq.get("ftp://speedtest.tele2.net/1KB.zip");
    assert(rs.code == 226);
    assert(rs.responseBody.length == 1024);
    info("ftp get  ", "ftp://ftp.uni-bayreuth.de/README");
    rs = rq.get("ftp://ftp.uni-bayreuth.de/README");
    assert(rs.code == 226);
    info("ftp post ", "ftp://speedtest.tele2.net/upload/TEST.TXT");
    rs = rq.post("ftp://speedtest.tele2.net/upload/TEST.TXT", "another test, ignore please\n".representation);
    assert(rs.code == 226);
    info("ftp get  ", "ftp://ftp.iij.ad.jp/pub/FreeBSD/README.TXT");
    rs = rq.get("ftp://ftp.iij.ad.jp/pub/FreeBSD/README.TXT");
    assert(rs.code == 226);
    info("testing ftp - done.");
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
public auto getContent(A...)(string url) {
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
public auto getContent(A...)(string url, string[string] args) {
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
public auto getContent(A...)(string url, QueryParam[] args) {
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
public auto getContent(A...)(string url, A args) if (args.length > 1 && args.length % 2 == 0 ) {
    return Request().
            get(url, queryParams(args)).
            responseBody;
}

///
package unittest {
    import std.algorithm;
    import std.stdio;
    import std.json;
    globalLogLevel(LogLevel.info);
    info("Test getContent");
    auto r = getContent("https://httpbin.org/stream/20");
    assert(r.splitter('\n').filter!("a.length>0").count == 20);
    r = getContent("ftp://speedtest.tele2.net/1KB.zip");
    assert(r.length == 1024);
    r = getContent("https://httpbin.org/get", ["a":"b", "c":"d"]);

    string name = "user", sex = "male";
    int    age = 42;
    r = getContent("https://httpbin.org/get", "name", name, "age", age, "sex", sex);

    info("Test receiveAsRange with GET");
    auto rq = Request();
    rq.useStreaming = true;
    rq.bufferSize = 16;
    auto rs = rq.get("http://httpbin.org/stream/20");
    auto stream = rs.receiveAsRange();
    ubyte[] streamedContent;
    while( !stream.empty() ) {
        streamedContent ~= stream.front;
        stream.popFront();
    }
    rq = Request();
    rs = rq.get("http://httpbin.org/stream/20");
    assert(streamedContent == rs.responseBody.data);
    rq.useStreaming = true;
    streamedContent.length = 0;
    rs = rq.get("ftp://speedtest.tele2.net/1KB.zip");
    stream = rs.receiveAsRange;
    while( !stream.empty() ) {
        streamedContent ~= stream.front;
        stream.popFront();
    }
    assert(streamedContent.length == 1024);
}
///
package unittest {
    globalLogLevel(LogLevel.info);
    info("Test get in parallel");
    import std.stdio;
    import std.parallelism;
    import std.algorithm;
    import std.string;
    import core.atomic;
    
    immutable auto urls = [
        "http://httpbin.org/stream/10",
        "https://httpbin.org/stream/20",
        "http://httpbin.org/stream/30",
        "https://httpbin.org/stream/40",
        "http://httpbin.org/stream/50",
        "https://httpbin.org/stream/60",
        "http://httpbin.org/stream/70",
    ];
    
    defaultPoolThreads(3);
    
    shared short lines;
    
    foreach(url; parallel(urls)) {
        atomicOp!"+="(lines, getContent(url).splitter("\n").count);
    }
    assert(lines == 287);
}

/**
 * Call post and return response content.
 */
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
    info("Test postContent");
    auto r = postContent("http://httpbin.org/post", `{"a":"b", "c":1}`, "application/json");
    assert(parseJSON(r.data).object["json"].object["c"].integer == 1);

    /// ftp upload from range
    info("Test postContent ftp");
    r = postContent("ftp://speedtest.tele2.net/upload/TEST.TXT", "test, ignore please\n".representation);
    assert(r.length == 0);

    /// Posting to forms (for small data)
    ///
    /// posting query parameters using "application/x-www-form-urlencoded"
    info("Test postContent using query params");
    postContent("http://httpbin.org/post", queryParams("first", "a", "second", 2));

    /// posting using multipart/form-data (large data and files). See docs fot HTTPRequest
    info("Test postContent form");
    MultipartForm form;
    form.add(formData(/* field name */ "greeting", /* content */ cast(ubyte[])"hello"));
    postContent("http://httpbin.org/post", form);

    /// you can do this using Request struct to access response details
    info("Test postContent form via Request()");
    auto rq = Request();
    form = MultipartForm().add(formData(/* field name */ "greeting", /* content */ cast(ubyte[])"hello"));
    auto rs = rq.post("http://httpbin.org/post", form);
    assert(rs.code == 200);

    info("Test receiveAsRange with POST");
    rq = Request();
    rq.useStreaming = true;
    rq.bufferSize = 16;
    string s = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    rs = rq.post("http://httpbin.org/post", s.representation.chunks(10), "application/octet-stream");
    auto stream = rs.receiveAsRange();
    ubyte[] streamedContent;
    while( !stream.empty() ) {
        streamedContent ~= stream.front;
        stream.popFront();
    }
    rq = Request();
    rs = rq.post("http://httpbin.org/post", s.representation.chunks(10), "application/octet-stream");
    assert(streamedContent == rs.responseBody.data);

}

