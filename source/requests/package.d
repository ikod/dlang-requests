module requests;

public import requests.http;
public import requests.ftp;
public import requests.streams;
public import requests.base;
public import requests.uri;
public import requests.request;
public import requests.pool;

import std.datetime;
import std.conv;
import std.experimental.logger;
import requests.utils;

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
    auto json = parseJSON(cast(string)rs.responseBody.data).object["args"].object;
    assert(json["c"].str == " d");
    assert(json["a"].str == "b");

    rq = Request();
    rq.keepAlive = true;
    {
        info("Check handling incomplete status line");
        rs = rq.get(httpbinUrl ~ "incomplete");
        if (httpbinUrl != "http://httpbin.org/") {
            assert(rs.code==600);
        }
    }
    // handmade json
    info("Check POST json");
    rs = rq.post(httpbinUrl ~ "post?b=x", `{"a":"b ", "c":[1,2,3]}`, "application/json");
    assert(rs.code==200);
    json = parseJSON(cast(string)rs.responseBody.data).object["args"].object;
    assert(json["b"].str == "x");
    json = parseJSON(cast(string)rs.responseBody.data).object["json"].object;
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
        if (httpbinUrl != "http://httpbin.org/" ) {
            assert(rs.code==200);
            auto data = fromJsonArrayToStr(parseJSON(cast(string)rs.responseBody).object["data"]);
            assert(data=="abcdefgh\n12345678\n");
        }
        f.close();
    }
    // ranges
    {
        info("Check POST chunked from lineSplitter");
        auto s = lineSplitter("one,\ntwo,\nthree.");
        rs = rq.exec!"POST"(httpbinUrl ~ "post", s, "application/octet-stream");
        if (httpbinUrl != "http://httpbin.org/" ) {
            assert(rs.code==200);
            auto data = fromJsonArrayToStr(parseJSON(cast(string)rs.responseBody).object["data"]);
            assert(data=="one,two,three.");
        }
    }
    {
        info("Check POST chunked from array");
        auto s = ["one,", "two,", "three."];
        rs = rq.post(httpbinUrl ~ "post", s, "application/octet-stream");
        if (httpbinUrl != "http://httpbin.org/" ) {
            assert(rs.code==200);
            auto data = fromJsonArrayToStr(parseJSON(cast(string)rs.responseBody).object["data"]);
            assert(data=="one,two,three.");
        }
    }
    {
        info("Check POST chunked using std.range.chunks()");
        auto s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        rs = rq.post(httpbinUrl ~ "post", s.representation.chunks(10), "application/octet-stream");
        if (httpbinUrl != "http://httpbin.org/") {
            assert(rs.code==200);
            auto data = fromJsonArrayToStr(parseJSON(cast(string)rs.responseBody).object["data"]);
            assert(data==s);
        }
    }
    // associative array
    rs = rq.post(httpbinUrl ~ "post", ["a":"b ", "c":"d"]);
    assert(rs.code==200);
    auto form = parseJSON(cast(string)rs.responseBody.data).object["form"].object;
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
    json = parseJSON(cast(string)rs.responseBody.data).object["cookies"].object;
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
    assert(streamedContent.length == rs.responseBody.data.length);
    info("Test postContent");
    r = postContent(httpbinUrl ~ "post", `{"a":"b", "c":1}`, "application/json");
    assert(parseJSON(cast(string)r).object["json"].object["c"].integer == 1);

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

    /// put content using multipart/form-data (large data and files). See docs fot HTTPRequest
    info("Test putContent form");
    mpform = MultipartForm();
    mpform.add(formData(/* field name */ "greeting", /* content */ cast(ubyte[])"hello"));
    putContent(httpbinUrl ~ "put", mpform);

    info("Test delContent");
    delContent(httpbinUrl ~ "delete");

    /// you can do this using Request struct to access response details
    info("Test post form via Request()");
    rq = Request();
    mpform = MultipartForm().add(formData(/* field name */ "greeting", /* content */ cast(ubyte[])"hello"));
    rs = rq.post(httpbinUrl ~ "post", mpform);
    assert(rs.code == 200);

    info("Test put form via Request()");
    rq = Request();
    mpform = MultipartForm().add(formData(/* field name */ "greeting", /* content */ cast(ubyte[])"hello"));
    rs = rq.put(httpbinUrl ~ "put", mpform);
    assert(rs.code == 200);

    info("Test del via Request()");
    rq = Request();
    rs = rq.del(httpbinUrl ~ "delete");
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


    info("Test POST'ing from Rank(2) range with user-provided Content-Length");
    rq = Request();
    rq.addHeaders(["content-length": to!string(s.length)]);
    rs = rq.post(httpbinUrl ~ "post", s.representation.chunks(10), "application/octet-stream");
    auto flat_content = parseJSON(cast(string)rs.responseBody().data).object["data"];
    if ( flat_content.type == JSON_TYPE.STRING ) {
        // httpbin.org returns string in "data"
        assert(s == flat_content.str);
    } else {
        // internal httpbin server return array ob bytes
        assert(s.representation == flat_content.array.map!(i => i.integer).array);
    }

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
/// Call put and return response content.
///
public auto putContent(A...)(string url, A args) {
    auto rq = Request();
    auto rs = rq.put(url, args);
    return rs.responseBody;
}

///
/// Call put and return response content.
///
public auto delContent(A...)(string url, A args) {
    auto rq = Request();
    auto rs = rq.del(url, args);
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
    info("Test getContent(ftp)");
    auto r = getContent("ftp://speedtest.tele2.net/1KB.zip");
    assert(r.length == 1024);

    info("Test postContent ftp");
    r = postContent("ftp://speedtest.tele2.net/upload/TEST.TXT", "test, ignore please\n".representation);
    assert(r.length == 0);

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
    rq.authenticator = new BasicAuthentication("anonymous", "request@");
    rs = rq.get("ftp://ftp.iij.ad.jp/pub/FreeBSD/README.TXT");
    assert(rs.code == 226);
    info("testing ftp - done.");
}

