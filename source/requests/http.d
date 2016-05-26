module requests.http;

private:
import std.algorithm;
import std.array;
import std.conv;
import std.datetime;
import std.exception;
import std.format;
import std.stdio;
import std.range;
import std.socket;
import std.string;
import std.traits;
import std.typecons;
import std.experimental.logger;
import core.thread;
import core.stdc.errno;

import requests.streams;
import requests.uri;
import requests.utils;
import requests.base;

static this() {
    globalLogLevel(LogLevel.error);
}

static immutable ushort[] redirectCodes = [301, 302, 303];

static string urlEncoded(string p) pure @safe {
    immutable string[dchar] translationTable = [
        ' ':  "%20", '!': "%21", '*': "%2A", '\'': "%27", '(': "%28", ')': "%29",
        ';':  "%3B", ':': "%3A", '@': "%40", '&':  "%26", '=': "%3D", '+': "%2B",
        '$':  "%24", ',': "%2C", '/': "%2F", '?':  "%3F", '#': "%23", '[': "%5B",
        ']':  "%5D", '%': "%25",
    ];
    return p.translate(translationTable);
}
unittest {
    assert(urlEncoded(`abc !#$&'()*+,/:;=?@[]`) == "abc%20%21%23%24%26%27%28%29%2A%2B%2C%2F%3A%3B%3D%3F%40%5B%5D");
}

public class TimeoutException: Exception {
    this(string msg, string file = __FILE__, size_t line = __LINE__) @safe pure {
        super(msg, file, line);
    }
}

public interface Auth {
    string[string] authHeaders(string domain);
}
/**
 * Basic authentication.
 * Adds $(B Authorization: Basic) header to request.
 */
public class BasicAuthentication: Auth {
    private {
        string   _username, _password;
        string[] _domains;
    }
    /// Constructor.
    /// Params:
    /// username = username
    /// password = password
    /// domains = not used now
    /// 
    this(string username, string password, string[] domains = []) {
        _username = username;
        _password = password;
        _domains = domains;
    }
    override string[string] authHeaders(string domain) {
        import std.base64;
        string[string] auth;
        auth["Authorization"] = "Basic " ~ to!string(Base64.encode(cast(ubyte[])"%s:%s".format(_username, _password)));
        return auth;
    }
}


///
/// Response - result of request execution.
///
/// Response.code - response HTTP code.
/// Response.status_line - received HTTP status line.
/// Response.responseHeaders - received headers.
/// Response.responseBody - container for received body
/// Response.history - for redirected responses contain all history
/// 
    public class HTTPResponse : Response {
    private {
//        ushort         __code;
        string         __status_line;
        string[string] __responseHeaders;
//        Buffer!ubyte   __responseBody;
        HTTPResponse[]     __history; // redirects history
        SysTime        __startedAt, __connectedAt, __requestSentAt, __finishedAt;
    }
   ~this() {
        __responseHeaders = null;
        __history.length = 0;
    }
    mixin(getter("code"));
    mixin(getter("status_line"));
    mixin(getter("responseHeaders"));
//    @property auto responseBody() inout pure @safe nothrow {
//        return __responseBody;
//    }
    mixin(getter("history"));
    private {
        mixin(setter("code"));
        mixin(setter("status_line"));
        mixin(setter("responseHeaders"));
    }
    @property auto getStats() const pure @safe {
        alias statTuple = Tuple!(Duration, "connectTime",
                                 Duration, "sendTime",
                                 Duration, "recvTime");
        statTuple stat;
        stat.connectTime = __connectedAt - __startedAt;
        stat.sendTime = __requestSentAt - __connectedAt;
        stat.recvTime = __finishedAt - __requestSentAt;
        return stat;
    }
}
/**
 * Struct to send multiple files in POST request.
 */
public struct PostFile {
    /// Path to the file to send.
    string fileName;
    /// Name of the field (if empty - send file base name)
    string fieldName;
    /// contentType of the file if not empty
    string contentType;
}
///
/// Request.
/// Configurable parameters:
/// $(B headers) - add any additional headers you'd like to send.
/// $(B authenticator) - class to send auth headers.
/// $(B keepAlive) - set true for keepAlive requests. default false.
/// $(B maxRedirects) - maximum number of redirects. default 10.
/// $(B maxHeadersLength) - maximum length of server response headers. default = 32KB.
/// $(B maxContentLength) - maximun content length. delault = 5MB.
/// $(B bufferSize) - send and receive buffer size. default = 16KB.
/// $(B verbosity) - level of verbosity(0 - nothing, 1 - headers, 2 - headers and body progress). default = 0.
/// $(B proxy) - set proxy url if needed. default - null.
/// 
public struct HTTPRequest {
    private {
        enum           __preHeaders = [
            "Accept-Encoding": "gzip, deflate",
            "User-Agent":      "dlang-requests"
        ];
        string         __method = "GET";
        URI            __uri;
        string[string] __headers;
        string[]       __filteredHeaders;
        Auth           __authenticator;
        bool           __keepAlive = true;
        uint           __maxRedirects = 10;
        size_t         __maxHeadersLength = 32 * 1024; // 32 KB
        size_t         __maxContentLength = 5 * 1024 * 1024; // 5MB
        ptrdiff_t      __contentLength;
        SocketStream   __stream;
        Duration       __timeout = 30.seconds;
        HTTPResponse       __response;
        HTTPResponse[]     __history; // redirects history
        size_t         __bufferSize = 16*1024; // 16k
        uint           __verbosity = 0;  // 0 - no output, 1 - headers, 2 - headers+body info
        DataPipe!ubyte __bodyDecoder;
        DecodeChunked  __unChunker;
        string         __proxy;
    }

    mixin(getter("keepAlive"));
    mixin(setter("keepAlive"));
    mixin(getter("method"));
    mixin(setter("method"));
    mixin(getter("timeout"));
    mixin(setter("timeout"));
    mixin(setter("authenticator"));
    mixin(getter("maxContentLength"));
    mixin(setter("maxContentLength"));
    mixin(getter("maxRedirects"));
    mixin(setter("maxRedirects"));
    mixin(getter("maxHeadersLength"));
    mixin(setter("maxHeadersLength"));
    mixin(getter("bufferSize"));
    mixin(setter("bufferSize"));
    mixin(getter("verbosity"));
    mixin(setter("verbosity"));
    mixin(setter("proxy"));

    this(string uri) {
        __uri = URI(uri);
    }
   ~this() {
        if ( __stream && __stream.isConnected) {
            __stream.close();
        }
        __stream = null;
        __headers = null;
        __authenticator = null;
        __history = null;
    }

    @property void uri(in URI newURI) {
        handleURLChange(__uri, newURI);
        __uri = newURI;
    }
    /// Add headers to request
    /// Params:
    /// headers = headers to send.
    void addHeaders(in string[string] headers) {
        foreach(pair; headers.byKeyValue) {
            __headers[pair.key] = pair.value;
        }
    }
    /// Remove headers from request
    /// Params:
    /// headers = headers to remove.
    void removeHeaders(in string[] headers) pure {
        __filteredHeaders ~= headers;
    }
    ///
    /// compose headers to send
    /// 
    private @property string[string] headers() {
        string[string] generatedHeaders = __preHeaders;

        if ( __authenticator ) {
            __authenticator.
                authHeaders(__uri.host).
                byKeyValue.
                each!(pair => generatedHeaders[pair.key] = pair.value);
        }

        generatedHeaders["Connection"] = __keepAlive?"Keep-Alive":"Close";
        generatedHeaders["Host"] = __uri.host;

        if ( __uri.scheme !in standard_ports || __uri.port != standard_ports[__uri.scheme] ) {
            generatedHeaders["Host"] ~= ":%d".format(__uri.port);
        }

        __headers.byKey.each!(h => generatedHeaders[h] = __headers[h]);

        __filteredHeaders.each!(h => generatedHeaders.remove(h));

        return generatedHeaders;
    }
    ///
    /// Build request string.
    /// Handle proxy and query parameters.
    /// 
    private @property string requestString(string[string] params = null) {
        if ( __proxy ) {
            return "%s %s HTTP/1.1\r\n".format(__method, __uri.uri);
        }
        auto query = __uri.query.dup;
        if ( params ) {
            query ~= params2query(params);
            if ( query[0] != '?' ) {
                query = "?" ~ query;
            }
        }
        return "%s %s%s HTTP/1.1\r\n".format(__method, __uri.path, query);
    }
    ///
    /// encode parameters and build query part of the url
    /// 
    private static string params2query(string[string] params) {
        auto m = params.keys.
                        sort().
                        map!(a=>urlEncoded(a) ~ "=" ~ urlEncoded(params[a])).
                        join("&");
        return m;
    }
    unittest {
        assert(HTTPRequest.params2query(["c ":"d", "a":"b"])=="a=b&c%20=d");
    }
    ///
    /// Analyze received headers, take appropriate actions:
    /// check content length, attach unchunk and uncompress
    /// 
    private void analyzeHeaders(in string[string] headers) {

        __contentLength = -1;
        __unChunker = null;
        auto contentLength = "content-length" in headers;
        if ( contentLength ) {
            try {
                __contentLength = to!ptrdiff_t(*contentLength);
                if ( __contentLength > maxContentLength) {
                    throw new RequestException("ContentLength > maxContentLength (%d>%d)".
                                format(__contentLength, __maxContentLength));
                }
            } catch (ConvException e) {
                throw new RequestException("Can't convert Content-Length from %s".format(*contentLength));
            }
        }
        auto transferEncoding = "transfer-encoding" in headers;
        if ( transferEncoding ) {
            tracef("transferEncoding: %s", *transferEncoding);
            if ( *transferEncoding == "chunked") {
                __unChunker = new DecodeChunked();
                __bodyDecoder.insert(__unChunker);
            }
        }
        auto contentEncoding = "content-encoding" in headers;
        if ( contentEncoding ) switch (*contentEncoding) {
            default:
                throw new RequestException("Unknown content-encoding " ~ *contentEncoding);
            case "gzip":
            case "deflate":
                __bodyDecoder.insert(new Decompressor!ubyte);
        }
    }
    ///
    /// Called when we know that all headers already received in buffer
    /// 1. Split headers on lines
    /// 2. store status line, store response code
    /// 3. unfold headers if needed
    /// 4. store headers
    /// 
    private void parseResponseHeaders(ref Buffer!ubyte buffer) {
        string lastHeader;
        foreach(line; buffer.data!(string).split("\n").map!(l => l.stripRight)) {
            if ( ! __response.status_line.length ) {
                tracef("statusLine: %s", line);
                __response.status_line = line;
                if ( __verbosity >= 1 ) {
                    writefln("< %s", line);
                }
                auto parsed = line.split(" ");
                if ( parsed.length >= 3 ) {
                    __response.code = parsed[1].to!ushort;
                }
                continue;
            }
            if ( line[0] == ' ' || line[0] == '\t' ) {
                // unfolding https://tools.ietf.org/html/rfc822#section-3.1
                auto stored = lastHeader in __response.__responseHeaders;
                if ( stored ) {
                    *stored ~= line;
                }
                continue;
            }
            auto parsed = line.findSplit(":");
            auto header = parsed[0].toLower;
            auto value = parsed[2].strip;
            auto stored = __response.responseHeaders.get(header, null);
            if ( stored ) {
                value = stored ~ ", " ~ value;
            }
            __response.__responseHeaders[header] = value;
            if ( __verbosity >= 1 ) {
                writefln("< %s: %s", parsed[0], value);
            }

            tracef("Header %s = %s", header, value);
            lastHeader = header;
        }
    }

    ///
    /// Do we received \r\n\r\n?
    /// 
    private bool headersHaveBeenReceived(in ubyte[] data, ref Buffer!ubyte buffer, out string separator) pure const @safe {
        foreach(s; ["\r\n\r\n", "\n\n"]) {
            if ( data.canFind(s) || buffer.canFind(s) ) {
                separator = s;
                return true;
            }
        }
        return false;
    }

    private bool followRedirectResponse() {
        if ( __history.length >= __maxRedirects ) {
            return false;
        }
        auto location = "location" in __response.responseHeaders;
        if ( !location ) {
            return false;
        }
        __history ~= __response;
        auto connection = "connection" in __response.__responseHeaders;
        if ( !connection || *connection == "close" ) {
            tracef("Closing connection because of 'Connection: close' or no 'Connection' header");
            __stream.close();
        }
        URI oldURI = __uri;
        URI newURI = oldURI;
        try {
            newURI = URI(*location);
        } catch (UriException e) {
            trace("Can't parse Location:, try relative uri");
            newURI.path = *location;
            newURI.uri = newURI.recalc_uri;
        }
        handleURLChange(oldURI, newURI);
            oldURI = __response.URI;
        __uri = newURI;
        __response = new HTTPResponse;
        __response.URI = oldURI;
        __response.finalURI = newURI;
        return true;
    }
    ///
    /// If uri changed so that we have to change host or port, then we have to close socket stream
    /// 
    private void handleURLChange(in URI from, in URI to) {
        if ( __stream !is null && __stream.isConnected && 
            ( from.scheme != to.scheme || from.host != to.host || from.port != to.port) ) {
            tracef("Have to reopen stream, because of URI change");
            __stream.close();
        }
    }
    
    private void checkURL(string url, string file=__FILE__, size_t line=__LINE__) {
        if (url is null && __uri.uri == "" ) {
            throw new RequestException("No url configured", file, line);
        }
        
        if ( url !is null ) {
            URI newURI = URI(url);
            handleURLChange(__uri, newURI);
            __uri = newURI;
        }
    }
    ///
    /// Setup connection. Handle proxy and https case
    /// 
    private void setupConnection() {
        if ( !__stream || !__stream.isConnected ) {
            tracef("Set up new connection");
            URI   uri;
            if ( __proxy ) {
                // use proxy uri to connect
                uri.uri_parse(__proxy);
            } else {
                // use original uri
                uri = __uri;
            }
            final switch (uri.scheme) {
                case "http":
                    __stream = new TCPSocketStream().connect(uri.host, uri.port, __timeout);
                    break;
                case "https":
                    __stream = new SSLSocketStream().connect(uri.host, uri.port, __timeout);
                    break;
            }
        } else {
            tracef("Use old connection");
        }
    }
    ///
    /// Receive response after request we sent.
    /// Find headers, split on headers and body, continue to receive body
    /// 
    private void receiveResponse() {

        __stream.so.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, timeout);
        scope(exit) {
            __stream.so.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, 0.seconds);
        }

        __bodyDecoder = new DataPipe!ubyte();
        auto b = new ubyte[__bufferSize];
        scope(exit) {
            __bodyDecoder = null;
            __unChunker = null;
            b = null;
        }

        auto buffer = Buffer!ubyte();
        Buffer!ubyte ResponseHeaders, partialBody;
        size_t receivedBodyLength;
        ptrdiff_t read;
        string separator;
        
        while(true) {

            read = __stream.receive(b);
            tracef("read: %d", read);
            if ( read < 0 ) {
                version(Windows) {
                    if ( errno == 0 ) {
                        throw new TimeoutException("Timeout receiving headers");
                    }
                }
                version(Posix) {
                    if ( errno == EAGAIN ) {
                        throw new TimeoutException("Timeout receiving headers");
                    }
                    throw new ErrnoException("receiving Headers");
                }
            }
            if ( read == 0 ) {
                break;
            }
            
            auto data = b[0..read];
            buffer.put(data);
            if ( buffer.length > maxHeadersLength ) {
                throw new RequestException("Headers length > maxHeadersLength (%d > %d)".format(buffer.length, maxHeadersLength));
            }
            if ( headersHaveBeenReceived(data, buffer, separator) ) {
                auto s = buffer.data!(ubyte[]).findSplit(separator);
                ResponseHeaders = Buffer!ubyte(s[0]);
                partialBody = Buffer!ubyte(s[2]);
                receivedBodyLength += partialBody.length;
                parseResponseHeaders(ResponseHeaders);
                break;
            }
        }
        
        analyzeHeaders(__response.__responseHeaders);
        __bodyDecoder.put(partialBody);

        if ( __verbosity >= 2 ) {
            writefln("< %d bytes of body received", partialBody.length);
        }

        if ( __method == "HEAD" ) {
            // HEAD response have ContentLength, but have no body
            return;
        }

        while( true ) {
            if ( __contentLength >= 0 && receivedBodyLength >= __contentLength ) {
                trace("Body received.");
                break;
            }
            if ( __unChunker && __unChunker.done ) {
                break;
            }
            read = __stream.receive(b);
            if ( read < 0 ) {
                if ( errno == EAGAIN ) {
                    throw new TimeoutException("Timeout receiving body");
                }
                throw new ErrnoException("receiving body");
            }
            if ( __verbosity >= 2 ) {
                writefln("< %d bytes of body received", read);
            }
            tracef("read: %d", read);
            if ( read == 0 ) {
                trace("read done");
                break;
            }
            receivedBodyLength += read;
            __bodyDecoder.put(b[0..read].dup);
            __response.__responseBody.put(__bodyDecoder.get());
            tracef("receivedTotal: %d, contentLength: %d, bodyLength: %d", receivedBodyLength, __contentLength, __response.__responseBody.length);
        }
        __bodyDecoder.flush();
        __response.__responseBody.put(__bodyDecoder.get());
    }
    ///
    /// execute POST request.
    /// Send form-urlencoded data
    /// 
    /// Parameters:
    ///     url = url to request
    ///     rqData = data to send
    ///  Returns:
    ///     Response
    ///  Examples:
    ///  ------------------------------------------------------------------
    ///  rs = rq.exec!"POST"("http://httpbin.org/post", ["a":"b", "c":"d"]);
    ///  ------------------------------------------------------------------
    ///
    HTTPResponse exec(string method)(string url, string[string] rqData) if (method=="POST") {
        //
        // application/x-www-form-urlencoded
        //
        __method = method;

        __response = new HTTPResponse;
        checkURL(url);
        __response.URI = __uri;
        __response.finalURI = __uri;

    connect:
        __response.__startedAt = Clock.currTime;
        setupConnection();
        
        if ( !__stream.isConnected() ) {
            return __response;
        }
        __response.__connectedAt = Clock.currTime;

        string encoded = params2query(rqData);
        auto h = headers;
        h["Content-Type"] = "application/x-www-form-urlencoded";
        h["Content-Length"] = to!string(encoded.length);

        Appender!string req;
        req.put(requestString());
        h.byKeyValue.
            map!(kv => kv.key ~ ": " ~ kv.value ~ "\r\n").
                each!(h => req.put(h));
        req.put("\r\n");
        req.put(encoded);
        trace(req.data);

        if ( __verbosity >= 1 ) {
            req.data.splitLines.each!(a => writeln("> " ~ a));
        }

        auto rc = __stream.send(req.data());
        if ( rc == -1 ) {
            errorf("Error sending request: ", lastSocketError);
            return __response;
        }
        __response.__requestSentAt = Clock.currTime;

        receiveResponse();

        __response.__finishedAt = Clock.currTime;

        auto connection = "connection" in __response.__responseHeaders;
        if ( !connection || *connection == "close" ) {
            tracef("Closing connection because of 'Connection: close' or no 'Connection' header");
            __stream.close();
        }
        if ( canFind(redirectCodes, __response.__code) && followRedirectResponse() ) {
            if ( __method != "GET" ) {
                return this.get();
            }
            goto connect;
        }
        __response.__history = __history;
        return __response;
    }
    ///
    /// send file(s) using POST
    /// Parameters:
    ///     url = url
    ///     files = array of PostFile structures
    /// Returns:
    ///     Response
    /// Example:
    /// ---------------------------------------------------------------
    ///    PostFile[] files = [
    ///                   {fileName:"tests/abc.txt", fieldName:"abc", contentType:"application/octet-stream"}, 
    ///                   {fileName:"tests/test.txt"}
    ///               ];
    ///    rs = rq.exec!"POST"("http://httpbin.org/post", files);
    /// ---------------------------------------------------------------
    /// 
    HTTPResponse exec(string method="POST")(string url, PostFile[] files) {
        import std.uuid;
        import std.file;
        //
        // application/json
        //
        bool restartedRequest = false;
        
        __method = method;
        
        __response = new HTTPResponse;
        checkURL(url);
        __response.URI = __uri;
        __response.finalURI = __uri;
 
    connect:
        __response.__startedAt = Clock.currTime;
        setupConnection();
        
        if ( !__stream.isConnected() ) {
            return __response;
        }
        __response.__connectedAt = Clock.currTime;

        Appender!string req;
        req.put(requestString());
        
        string   boundary = randomUUID().toString;
        string[] partHeaders;
        size_t   contentLength;

        foreach(part; files) {
            string fieldName = part.fieldName ? part.fieldName : part.fileName;
            string h = "--" ~ boundary ~ "\r\n";
            h ~= `Content-Disposition: form-data; name="%s"; filename="%s"`.
                format(fieldName, part.fileName) ~ "\r\n";
            if ( part.contentType ) {
                h ~= "Content-Type: " ~ part.contentType ~ "\r\n";
            }
            h ~= "\r\n";
            partHeaders ~= h;
            contentLength += h.length + getSize(part.fileName) + "\r\n".length;
        }
        contentLength += "--".length + boundary.length + "--\r\n".length;

        auto h = headers;
        h["Content-Type"] = "multipart/form-data; boundary=" ~ boundary;
        h["Content-Length"] = to!string(contentLength);
        h.byKeyValue.
            map!(kv => kv.key ~ ": " ~ kv.value ~ "\r\n").
            each!(h => req.put(h));
        req.put("\r\n");
        
        trace(req.data);
        if ( __verbosity >= 1 ) {
            req.data.splitLines.each!(a => writeln("> " ~ a));
        }

        auto rc = __stream.send(req.data());
        if ( rc == -1 ) {
            errorf("Error sending request: ", lastSocketError);
            return __response;
        }
        foreach(hdr, f; zip(partHeaders, files)) {
            tracef("sending part headers <%s>", hdr);
            __stream.send(hdr);
            auto file = File(f.fileName, "rb");
            scope(exit) {
                file.close();
            }
            foreach(chunk; file.byChunk(16*1024)) {
                __stream.send(chunk);
            }
            __stream.send("\r\n");
        }
        __stream.send("--" ~ boundary ~ "--\r\n");
        __response.__requestSentAt = Clock.currTime;

        receiveResponse();

        if ( __response.__responseHeaders.length == 0 
            && __keepAlive
            && !restartedRequest
            && __method == "GET"
            ) {
            tracef("Server closed keepalive connection");
            __stream.close();
            restartedRequest = true;
            goto connect;
        }

        __response.__finishedAt = Clock.currTime;
        ///
        auto connection = "connection" in __response.__responseHeaders;
        if ( !connection || *connection == "close" ) {
            tracef("Closing connection because of 'Connection: close' or no 'Connection' header");
            __stream.close();
        }
        if ( canFind(redirectCodes, __response.__code) && followRedirectResponse() ) {
            if ( __method != "GET" ) {
                return this.get();
            }
            goto connect;
        }
        __response.__history = __history;
        ///
        return __response;
    }
    ///
    /// POST data from some string(with Content-Length), or from range of strings (use Transfer-Encoding: chunked)
    /// 
    /// Parameters:
    ///    url = url
    ///    content = string or input range
    ///    contentType = content type
    ///  Returns:
    ///     Response
    ///  Examples:
    ///  ---------------------------------------------------------------------------------------------------------
    ///      rs = rq.exec!"POST"("http://httpbin.org/post", "привiт, свiт!", "application/octet-stream");
    ///      
    ///      auto s = lineSplitter("one,\ntwo,\nthree.");
    ///      rs = rq.exec!"POST"("http://httpbin.org/post", s, "application/octet-stream");
    ///      
    ///      auto s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    ///      rs = rq.exec!"POST"("http://httpbin.org/post", s.representation.chunks(10), "application/octet-stream");
    ///
    ///      auto f = File("tests/test.txt", "rb");
    ///      rs = rq.exec!"POST"("http://httpbin.org/post", f.byChunk(3), "application/octet-stream");
    ///  --------------------------------------------------------------------------------------------------------
    HTTPResponse exec(string method="POST", R)(string url, R content, string contentType="text/html")
        if ( (rank!R == 1) //isSomeString!R
            || (rank!R == 2 && isSomeChar!(Unqual!(typeof(content.front.front)))) 
            || (rank!R == 2 && (is(Unqual!(typeof(content.front.front)) == ubyte)))
            )
    {
        //
        // application/json
        //
        bool restartedRequest = false;
        
        __method = method;
        
        __response = new HTTPResponse;
        checkURL(url);
        __response.URI = __uri;
        __response.finalURI = __uri;

    connect:
        __response.__startedAt = Clock.currTime;
        setupConnection();
        
        if ( !__stream.isConnected() ) {
            return __response;
        }
        __response.__connectedAt = Clock.currTime;

        Appender!string req;
        req.put(requestString());

        auto h = headers;
        h["Content-Type"] = contentType;
        static if ( rank!R == 1 ) {
            h["Content-Length"] = to!string(content.length);
        } else {
            h["Transfer-Encoding"] = "chunked";
        }
        h.byKeyValue.
            map!(kv => kv.key ~ ": " ~ kv.value ~ "\r\n").
            each!(h => req.put(h));
        req.put("\r\n");

        trace(req.data);
        if ( __verbosity >= 1 ) {
            req.data.splitLines.each!(a => writeln("> " ~ a));
        }

        auto rc = __stream.send(req.data());
        if ( rc == -1 ) {
            errorf("Error sending request: ", lastSocketError);
            return __response;
        }

        static if ( rank!R == 1) {
            __stream.send(content);
        } else {
            while ( !content.empty ) {
                auto chunk = content.front;
                auto chunkHeader = "%x\r\n".format(chunk.length);
                tracef("sending %s%s", chunkHeader, chunk);
                __stream.send(chunkHeader);
                __stream.send(chunk);
                __stream.send("\r\n");
                content.popFront;
            }
            tracef("sent");
            __stream.send("0\r\n\r\n");
        }
        __response.__requestSentAt = Clock.currTime;

        receiveResponse();

        if ( __response.__responseHeaders.length == 0 
            && __keepAlive
            && !restartedRequest
            && __method == "GET"
            ) {
            tracef("Server closed keepalive connection");
            __stream.close();
            restartedRequest = true;
            goto connect;
        }

        __response.__finishedAt = Clock.currTime;

        ///
        auto connection = "connection" in __response.__responseHeaders;
        if ( !connection || *connection == "close" ) {
            tracef("Closing connection because of 'Connection: close' or no 'Connection' header");
            __stream.close();
        }
        if ( canFind(redirectCodes, __response.__code) && followRedirectResponse() ) {
            if ( __method != "GET" ) {
                return this.get();
            }
            goto connect;
        }
        ///
        __response.__history = __history;
        return __response;
    }
    ///
    /// Send request without data
    /// Request parameters will be encoded into request string
    /// Parameters:
    ///     url = url
    ///     params = request parameters
    ///  Returns:
    ///     Response
    ///  Examples:
    ///  ---------------------------------------------------------------------------------
    ///     rs = Request().exec!"GET"("http://httpbin.org/get", ["c":"d", "a":"b"]);
    ///  ---------------------------------------------------------------------------------
    ///     
    HTTPResponse exec(string method="GET")(string url = null, string[string] params = null) if (method != "POST")
    {

        __method = method;
        __response = new HTTPResponse;
        __history.length = 0;
        bool restartedRequest = false; // True if this is restarted keepAlive request

        checkURL(url);
        __response.URI = __uri;
        __response.finalURI = __uri;
    connect:
        __response.__startedAt = Clock.currTime;
        setupConnection();

        if ( !__stream.isConnected() ) {
            return __response;
        }
        __response.__connectedAt = Clock.currTime;

        Appender!string req;
        req.put(requestString(params));
        headers.byKeyValue.
            map!(kv => kv.key ~ ": " ~ kv.value ~ "\r\n").
            each!(h => req.put(h));
        req.put("\r\n");
        trace(req.data);

        if ( __verbosity >= 1 ) {
            req.data.splitLines.each!(a => writeln("> " ~ a));
        }
        auto rc = __stream.send(req.data());
        if ( rc == -1 ) {
            errorf("Error sending request: ", lastSocketError);
            return __response;
        }
        __response.__requestSentAt = Clock.currTime;

        receiveResponse();

        if ( __response.__responseHeaders.length == 0 
            && __keepAlive
            && !restartedRequest
            && __method == "GET"
        ) {
            tracef("Server closed keepalive connection");
            __stream.close();
            restartedRequest = true;
            goto connect;
        }
        __response.__finishedAt = Clock.currTime;

        ///
        auto connection = "connection" in __response.__responseHeaders;
        if ( !connection || *connection == "close" ) {
            tracef("Closing connection because of 'Connection: close' or no 'Connection' header");
            __stream.close();
        }
        if ( __verbosity >= 1 ) {
            writeln(">> Connect time: ", __response.__connectedAt - __response.__startedAt);
            writeln(">> Request send time: ", __response.__requestSentAt - __response.__connectedAt);
            writeln(">> Response recv time: ", __response.__finishedAt - __response.__requestSentAt);
        }
        if ( canFind(redirectCodes, __response.__code) && followRedirectResponse() ) {
            if ( __method != "GET" ) {
                return this.get();
            }
            goto connect;
        }
        ///
        __response.__history = __history;
        return __response;
    }
    ///
    /// GET request. Simple wrapper over exec!"GET"
    /// Params:
    /// args = request parameters. see exec docs.
    ///
    HTTPResponse get(A...)(A args) {
        return exec!"GET"(args);
    }
    ///
    /// POST request. Simple wrapper over exec!"POST"
    /// Params:
    /// args = request parameters. see exec docs.
    ///
    HTTPResponse post(A...)(string uri, A args) {
        return exec!"POST"(uri, args);
    }
}

///
public unittest {
    import std.json;
    globalLogLevel(LogLevel.info);
    tracef("http tests - start");

    auto rq = HTTPRequest();
    auto rs = rq.get("https://httpbin.org/");
    assert(rs.code==200);
    assert(rs.responseBody.length > 0);
    rs = HTTPRequest().get("http://httpbin.org/get", ["c":" d", "a":"b"]);
    assert(rs.code == 200);
    auto json = parseJSON(rs.responseBody.data).object["args"].object;
    assert(json["c"].str == " d");
    assert(json["a"].str == "b");

    globalLogLevel(LogLevel.info);
    rq = HTTPRequest();
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
    rq = HTTPRequest();
    rq.keepAlive = true;
    rs = rq.get("http://httpbin.org/gzip");
    assert(rs.code==200);
    info("gzip - ok");
    rs = rq.get("http://httpbin.org/deflate");
    assert(rs.code==200);
    info("deflate - ok");

    info("Check redirects");
    globalLogLevel(LogLevel.info);
    rq = HTTPRequest();
    rq.keepAlive = true;
    rs = rq.get("http://httpbin.org/relative-redirect/2");
    assert(rs.history.length == 2);
    assert(rs.code==200);
//    rq = Request();
//    rq.keepAlive = true;
//    rq.proxy = "http://localhost:8888/";
    rs = rq.get("http://httpbin.org/absolute-redirect/2");
    assert(rs.history.length == 2);
    assert(rs.code==200);
//    rq = Request();
    rq.maxRedirects = 2;
    rq.keepAlive = false;
    rs = rq.get("https://httpbin.org/absolute-redirect/3");
    assert(rs.history.length == 2);
    assert(rs.code==302);

    info("Check utf8 content");
    globalLogLevel(LogLevel.info);
    rq = HTTPRequest();
    rs = rq.get("http://httpbin.org/encoding/utf8");
    assert(rs.code==200);

    info("Check chunked content");
    globalLogLevel(LogLevel.info);
    rq = HTTPRequest();
    rq.keepAlive = true;
    rq.bufferSize = 16*1024;
    rs = rq.get("http://httpbin.org/range/1024");
    assert(rs.code==200);
    assert(rs.responseBody.length==1024);

    info("Check basic auth");
    globalLogLevel(LogLevel.info);
    rq = HTTPRequest();
    rq.authenticator = new BasicAuthentication("user", "passwd");
    rs = rq.get("http://httpbin.org/basic-auth/user/passwd");
    assert(rs.code==200);
 
    globalLogLevel(LogLevel.info);
    info("Check exception handling, error messages are OK");
    rq = HTTPRequest();
    rq.timeout = 1.seconds;
    assertThrown!TimeoutException(rq.get("http://httpbin.org/delay/3"));
    assertThrown!ConnectError(rq.get("http://0.0.0.0:65000/"));
    assertThrown!ConnectError(rq.get("http://1.1.1.1/"));
    assertThrown!ConnectError(rq.get("http://gkhgkhgkjhgjhgfjhgfjhgf/"));

    globalLogLevel(LogLevel.info);
    info("Check limits");
    rq = HTTPRequest();
    rq.maxContentLength = 1;
    assertThrown!RequestException(rq.get("http://httpbin.org/"));
    rq = HTTPRequest();
    rq.maxHeadersLength = 1;
    assertThrown!RequestException(rq.get("http://httpbin.org/"));
    tracef("http tests - ok");
}
