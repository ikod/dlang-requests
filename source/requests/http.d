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

public alias Cookie     = Tuple!(string, "path", string, "domain", string, "attr", string, "value");
public alias QueryParam = Tuple!(string, "key", string, "value");

static immutable ushort[] redirectCodes = [301, 302, 303];
static immutable uint     defaultBufferSize = 12*1024;

static string urlEncoded(string p) pure @safe {
    immutable string[dchar] translationTable = [
        ' ':  "%20", '!': "%21", '*': "%2A", '\'': "%27", '(': "%28", ')': "%29",
        ';':  "%3B", ':': "%3A", '@': "%40", '&':  "%26", '=': "%3D", '+': "%2B",
        '$':  "%24", ',': "%2C", '/': "%2F", '?':  "%3F", '#': "%23", '[': "%5B",
        ']':  "%5D", '%': "%25",
    ];
    return p.translate(translationTable);
}
package unittest {
    assert(urlEncoded(`abc !#$&'()*+,/:;=?@[]`) == "abc%20%21%23%24%26%27%28%29%2A%2B%2C%2F%3A%3B%3D%3F%40%5B%5D");
}

public class TimeoutException: Exception {
    this(string msg, string file = __FILE__, size_t line = __LINE__) @safe pure {
        super(msg, file, line);
    }
}

public class MaxRedirectsException: Exception {
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
///
///
public auto queryParams(T...)(T params) pure nothrow @safe
{
    static assert (T.length % 2 == 0, "wrong args count");
    
    QueryParam[] output;
    output.reserve = T.length / 2;
    
    void queryParamsHelper(T...)(T params, ref QueryParam[] output)
    {
        static if (T.length > 0)
        {
            output ~= QueryParam(params[0].to!string, params[1].to!string);
            queryParamsHelper(params[2..$], output);
        }
    }

    queryParamsHelper(params, output);
    return output;
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
        string         _status_line;

        HTTPResponse[] _history; // redirects history
        SysTime        _startedAt, _connectedAt, _requestSentAt, _finishedAt;

        mixin(Setter!string("status_line"));
    }

    ~this() {
        _responseHeaders = null;
        _history.length = 0;
    }

    mixin(Getter!string("status_line"));
    @property final string[string] responseHeaders() @safe @nogc nothrow {
        return _responseHeaders;
    }
    @property final HTTPResponse[] history() @safe @nogc nothrow {
        return _history;
    }

    @property auto getStats() const pure @safe {
        alias statTuple = Tuple!(Duration, "connectTime",
                                 Duration, "sendTime",
                                 Duration, "recvTime");
        statTuple stat;
        stat.connectTime = _connectedAt - _startedAt;
        stat.sendTime = _requestSentAt - _connectedAt;
        stat.recvTime = _finishedAt - _requestSentAt;
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
/// This is File-like interface for sending data to multipart fotms
/// 
public interface FiniteReadable {
    /// size of the content
    abstract ulong  getSize();
    /// file-like read()
    abstract ubyte[] read();
}
///
/// Helper to create form elements from File.
/// Params:
/// name = name of the field in form
/// f = opened std.stio.File to send to server
/// parameters = optional parameters (most important are "filename" and "Content-Type")
/// 
public auto formData(string name, File f, string[string] parameters = null) {
    return MultipartForm.FormData(name, new FormDataFile(f), parameters);
}
///
/// Helper to create form elements from ubyte[].
/// Params:
/// name = name of the field in form
/// b = data to send to server
/// parameters = optional parameters (can be "filename" and "Content-Type")
/// 
public auto formData(string name, ubyte[] b, string[string] parameters = null) {
    return MultipartForm.FormData(name, new FormDataBytes(b), parameters);
}
public auto formData(string name, string b, string[string] parameters = null) {
    return MultipartForm.FormData(name, new FormDataBytes(b.dup.representation), parameters);
}
public class FormDataBytes : FiniteReadable {
    private {
        ulong   _size;
        ubyte[] _data;
        size_t  _offset;
        bool    _exhausted;
    }
    this(ubyte[] data) {
        _data = data;
        _size = data.length;
    }
    final override ulong getSize() {
        return _size;
    }
    final override ubyte[] read() {
        enforce( !_exhausted, "You can't read froum exhausted source" );
        size_t toRead = min(defaultBufferSize, _size - _offset);
        auto result = _data[_offset.._offset+toRead];
        _offset += toRead;
        if ( toRead == 0 ) {
            _exhausted = true;
        }
        return result;
    }
}
public class FormDataFile : FiniteReadable {
    import  std.file;
    private {
        File    _fileHandle;
        ulong   _fileSize;
        size_t  _processed;
        bool    _exhausted;
    }
    this(File file) {
        import std.file;
        _fileHandle = file;
        _fileSize = std.file.getSize(file.name);
    }
    final override ulong getSize() pure nothrow @safe {
        return _fileSize;
    }
    final override ubyte[] read() {
        enforce( !_exhausted, "You can't read froum exhausted source" );
        auto b = new ubyte[defaultBufferSize];
        auto r = _fileHandle.rawRead(b);
        auto toRead = min(r.length, _fileSize - _processed);
        if ( toRead == 0 ) {
            _exhausted = true;
        }
        _processed += toRead;
        return r[0..toRead];
    }
}
///
/// This struct used to bulld POST's to forms.
/// Each part have name and data. data is something that can be read-ed and have size.
/// For example this can be string-like object (wrapped for reading) or opened File.
/// 
public struct MultipartForm {
    package struct FormData {
        FiniteReadable  input;
        string          name;
        string[string]  parameters;
        this(string name, FiniteReadable i, string[string] parameters = null) {
            this.input = i;
            this.name = name;
            this.parameters = parameters;
        }
    }

    private FormData[] _sources;
    auto add(FormData d) {
        _sources ~= d;
        return this;
    }
    auto add(string name, FiniteReadable i, string[string]parameters = null) {
        _sources ~= FormData(name, i, parameters);
        return this;
    }
}
///
package unittest {
    /// This is example on usage files with MultipartForm data.
    /// For this example we have to create files which will be sent.
    import std.file;
    import std.path;
    globalLogLevel(LogLevel.info);
    info("Check POST files");
    /// preapare files
    auto tmpd = tempDir();
    auto tmpfname1 = tmpd ~ dirSeparator ~ "request_test1.txt";
    auto f = File(tmpfname1, "wb");
    f.rawWrite("file1 content\n");
    f.close();
    auto tmpfname2 = tmpd ~ dirSeparator ~ "request_test2.txt";
    f = File(tmpfname2, "wb");
    f.rawWrite("file2 content\n");
    f.close();
    ///
    /// Ok, files ready.
    /// Now we will prepare Form data
    /// 
    File f1 = File(tmpfname1, "rb");
    File f2 = File(tmpfname2, "rb");
    scope(exit) {
        f1.close();
        f2.close();
    }
    ///
    /// for each part we have to set field name, source (ubyte array or opened file) and optional filename and content-type
    /// 
    MultipartForm form = MultipartForm().
        add(formData("Field1", cast(ubyte[])"form field from memory")).
        add(formData("Field2", cast(ubyte[])"file field from memory", ["filename":"data2"])).
        add(formData("File1", f1, ["filename":"file1", "Content-Type": "application/octet-stream"])).
        add(formData("File2", f2, ["filename":"file2", "Content-Type": "application/octet-stream"]));
    /// everything ready, send request
    auto rq = HTTPRequest();
    auto rs = rq.post("http://httpbin.org/post", form);
}

///
/// Request.
/// Configurable parameters:
/// $(B method) - string, method to use (GET, POST, ...)
/// $(B headers) - string[string], add any additional headers you'd like to send.
/// $(B authenticator) - class Auth, class to send auth headers.
/// $(B keepAlive) - bool, set true for keepAlive requests. default true.
/// $(B maxRedirects) - uint, maximum number of redirects. default 10.
/// $(B maxHeadersLength) - size_t, maximum length of server response headers. default = 32KB.
/// $(B maxContentLength) - size_t, maximun content length. delault - 0 = unlimited.
/// $(B bufferSize) - size_t, send and receive buffer size. default = 16KB.
/// $(B verbosity) - uint, level of verbosity(0 - nothing, 1 - headers, 2 - headers and body progress). default = 0.
/// $(B proxy) - string, set proxy url if needed. default - null.
/// $(B cookie) - Tuple Cookie, Read/Write cookie You can get cookie setted by server, or set cookies before doing request.
/// $(B timeout) - Duration, Set timeout value for connect/receive/send.
/// 
public struct HTTPRequest {
    private {
        enum           _preHeaders = [
                            "Accept-Encoding": "gzip, deflate",
                            "User-Agent":      "dlang-requests"
                        ];
        string         _method = "GET";
        URI            _uri;
        string[string] _headers;
        string[]       _filteredHeaders;
        Auth           _authenticator;
        bool           _keepAlive = true;
        uint           _maxRedirects = 10;
        size_t         _maxHeadersLength = 32 * 1024; // 32 KB
        size_t         _maxContentLength; // 0 - Unlimited
        string         _proxy;
        uint           _verbosity = 0;  // 0 - no output, 1 - headers, 2 - headers+body info
        Duration       _timeout = 30.seconds;
        size_t         _bufferSize = defaultBufferSize; // 16k
        bool           _useStreaming; // return iterator instead of completed request

        SocketStream   _stream;
        HTTPResponse[] _history; // redirects history
        DataPipe!ubyte _bodyDecoder;
        DecodeChunked  _unChunker;
        long           _contentLength;
        long           _contentReceived;
        Cookie[]       _cookie;
    }
    package HTTPResponse   _response;

    mixin(Getter_Setter!string   ("method"));
    mixin(Getter_Setter!bool     ("keepAlive"));
    mixin(Getter_Setter!size_t   ("maxContentLength"));
    mixin(Getter_Setter!size_t   ("maxHeadersLength"));
    mixin(Getter_Setter!size_t   ("bufferSize"));
    mixin(Getter_Setter!uint     ("maxRedirects"));
    mixin(Getter_Setter!uint     ("verbosity"));
    mixin(Getter_Setter!string   ("proxy"));
    mixin(Getter_Setter!Duration ("timeout"));
    mixin(Setter!Auth            ("authenticator"));
    mixin(Getter_Setter!bool     ("useStreaming"));
    mixin(Getter!long            ("contentLength"));
    mixin(Getter!long            ("contentReceived"));

    @property final void cookie(Cookie[] s) pure @safe @nogc nothrow {
        _cookie = s;
    }
    
    @property final Cookie[] cookie() pure @safe @nogc nothrow {
        return _cookie;
    }    

    this(string uri) {
        _uri = URI(uri);
    }
   ~this() {
        if ( _stream && _stream.isConnected) {
            _stream.close();
        }
        _stream = null;
        _headers = null;
        _authenticator = null;
        _history = null;
        _bodyDecoder = null;
        _unChunker = null;
    }

    @property void uri(in URI newURI) {
        handleURLChange(_uri, newURI);
        _uri = newURI;
    }
    /// Add headers to request
    /// Params:
    /// headers = headers to send.
    void addHeaders(in string[string] headers) {
        foreach(pair; headers.byKeyValue) {
            _headers[pair.key] = pair.value;
        }
    }
    /// Remove headers from request
    /// Params:
    /// headers = headers to remove.
    void removeHeaders(in string[] headers) pure {
        _filteredHeaders ~= headers;
    }
    ///
    /// compose headers to send
    /// 
    private string[string] requestHeaders() {
        string[string] generatedHeaders = _preHeaders;

        if ( _authenticator ) {
            _authenticator.
                authHeaders(_uri.host).
                byKeyValue.
                each!(pair => generatedHeaders[pair.key] = pair.value);
        }

        generatedHeaders["Connection"] = _keepAlive?"Keep-Alive":"Close";
        generatedHeaders["Host"] = _uri.host;

        if ( _uri.scheme !in standard_ports || _uri.port != standard_ports[_uri.scheme] ) {
            generatedHeaders["Host"] ~= ":%d".format(_uri.port);
        }

        _headers.byKey.each!(h => generatedHeaders[h] = _headers[h]);

        if ( _cookie.length ) {
            auto cs = _cookie.
                filter!(c => _uri.path.pathMatches(c.path) && _uri.host.domainMatches(c.domain)).
                map!(c => "%s=%s".format(c.attr, c.value)).
                joiner(";");
            generatedHeaders["Cookie"] = "%s".format(cs);
        }

        _filteredHeaders.each!(h => generatedHeaders.remove(h));

        return generatedHeaders;
    }
    ///
    /// Build request string.
    /// Handle proxy and query parameters.
    /// 
    private @property string requestString(QueryParam[] params = null) {
        if ( _proxy ) {
            return "%s %s HTTP/1.1\r\n".format(_method, _uri.uri);
        }
        auto query = _uri.query.dup;
        if ( params ) {
            query ~= params2query(params);
            if ( query[0] != '?' ) {
                query = "?" ~ query;
            }
        }
        return "%s %s%s HTTP/1.1\r\n".format(_method, _uri.path, query);
    }
    ///
    /// encode parameters and build query part of the url
    /// 
    private static string params2query(in QueryParam[] params) pure @safe {
        return params.
                map!(a => "%s=%s".format(a.key.urlEncoded, a.value.urlEncoded)).
                join("&");
    }
    //
    package unittest {
        assert(params2query(queryParams("a","b", "c", " d "))=="a=b&c=%20d%20");
    }
    ///
    /// Analyze received headers, take appropriate actions:
    /// check content length, attach unchunk and uncompress
    /// 
    private void analyzeHeaders(in string[string] headers) {

        _contentLength = -1;
        _unChunker = null;
        auto contentLength = "content-length" in headers;
        if ( contentLength ) {
            try {
                _contentLength = to!long(*contentLength);
                if ( _maxContentLength && _contentLength > _maxContentLength) {
                    throw new RequestException("ContentLength > maxContentLength (%d>%d)".
                                format(_contentLength, _maxContentLength));
                }
            } catch (ConvException e) {
                throw new RequestException("Can't convert Content-Length from %s".format(*contentLength));
            }
        }
        auto transferEncoding = "transfer-encoding" in headers;
        if ( transferEncoding ) {
            tracef("transferEncoding: %s", *transferEncoding);
            if ( *transferEncoding == "chunked") {
                _unChunker = new DecodeChunked();
                _bodyDecoder.insert(_unChunker);
            }
        }
        auto contentEncoding = "content-encoding" in headers;
        if ( contentEncoding ) switch (*contentEncoding) {
            default:
                throw new RequestException("Unknown content-encoding " ~ *contentEncoding);
            case "gzip":
            case "deflate":
                _bodyDecoder.insert(new Decompressor!ubyte);
        }

    }
    ///
    /// Called when we know that all headers already received in buffer.
    /// This routine does not interpret headers content (see analyzeHeaders).
    /// 1. Split headers on lines
    /// 2. store status line, store response code
    /// 3. unfold headers if needed
    /// 4. store headers
    /// 
    private void parseResponseHeaders(ref Buffer!ubyte buffer) {
        string lastHeader;

        foreach(line; buffer.data!(string).split("\n").map!(l => l.stripRight)) {
            if ( ! _response.status_line.length ) {
                tracef("statusLine: %s", line);
                _response.status_line = line;
                if ( _verbosity >= 1 ) {
                    writefln("< %s", line);
                }
                auto parsed = line.split(" ");
                if ( parsed.length >= 3 ) {
                    _response.code = parsed[1].to!ushort;
                }
                continue;
            }
            if ( line[0] == ' ' || line[0] == '\t' ) {
                // unfolding https://tools.ietf.org/html/rfc822#section-3.1
                auto stored = lastHeader in _response._responseHeaders;
                if ( stored ) {
                    *stored ~= line;
                }
                continue;
            }
            auto parsed = line.findSplit(":");
            auto header = parsed[0].toLower;
            auto value = parsed[2].strip;

            if ( _verbosity >= 1 ) {
                writefln("< %s: %s", header, value);
            }

            lastHeader = header;
            tracef("Header %s = %s", header, value);

            if ( header != "set-cookie" ) {
                auto stored = _response.responseHeaders.get(header, null);
                if ( stored ) {
                    value = stored ~ ", " ~ value;
                }
                _response._responseHeaders[header] = value;
                continue;
            }
           _cookie ~= processCookie(value);
        }
    }
    ///
    /// Process Set-Cookie header from server response
    /// 
    private Cookie[] processCookie(string value ) pure {
        // cookie processing
        //
        // as we can't join several set-cookie lines in single line
        // < Set-Cookie: idx=7f2800f63c112a65ef5082957bcca24b; expires=Mon, 29-May-2017 00:31:25 GMT; path=/; domain=example.com
        // < Set-Cookie: idx=7f2800f63c112a65ef5082957bcca24b; expires=Mon, 29-May-2017 00:31:25 GMT; path=/; domain=example.com, cs=ip764-RgKqc-HvSkxRxdQQAKW8LA; path=/; domain=.example.com; HttpOnly
        //
        Cookie[] res;
        string[string] kv;
        auto fields = value.split(";").map!strip;
        while(!fields.empty) {
            auto s = fields.front.findSplit("=");
            fields.popFront;
            if ( s[1] != "=" ) {
                continue;
            }
            auto k = s[0];
            auto v = s[2];
            switch(k.toLower()) {
                case "domain":
                    k = "domain";
                    break;
                case "path":
                    k = "path";
                    break;
                case "expires":
                    continue;
                default:
                    break;
            }
            kv[k] = v;
        }
        if ( "domain" !in kv ) {
            kv["domain"] = _uri.host;
        }
        if ( "path" !in kv ) {
            kv["path"] = _uri.path;
        }
        auto domain = kv["domain"]; kv.remove("domain");
        auto path   = kv["path"];   kv.remove("path");
        foreach(pair; kv.byKeyValue) {
            auto _attr = pair.key;
            auto _value = pair.value;
            auto cookie = Cookie(path, domain, _attr, _value);
            res ~= cookie;
        }
        return res;
    }
    ///
    /// Do we received \r\n\r\n?
    /// 
    private bool headersHaveBeenReceived(in ubyte[] data, ref Buffer!ubyte buffer, out string separator) const @safe {
        foreach(s; ["\r\n\r\n", "\n\n"]) {
            if ( data.canFind(s) || buffer.canFind(s) ) {
                separator = s;
                return true;
            }
        }
        return false;
    }

    private bool followRedirectResponse() {
        if ( _history.length >= _maxRedirects ) {
            throw new MaxRedirectsException("%d redirects reached maxRedirects %d.".format(_history.length, _maxRedirects));
        }
        auto location = "location" in _response.responseHeaders;
        if ( !location ) {
            return false;
        }
        _history ~= _response;
        auto connection = "connection" in _response._responseHeaders;
        if ( !connection || *connection == "close" ) {
            tracef("Closing connection because of 'Connection: close' or no 'Connection' header");
            _stream.close();
        }
        URI oldURI = _uri;
        URI newURI = oldURI;
        try {
            newURI = URI(*location);
        } catch (UriException e) {
            trace("Can't parse Location:, try relative uri");
            newURI.path = *location;
            newURI.uri = newURI.recalc_uri;
        }
        handleURLChange(oldURI, newURI);
            oldURI = _response.uri;
        _uri = newURI;
        _response = new HTTPResponse;
        _response.uri = oldURI;
        _response.finalURI = newURI;
        return true;
    }
    ///
    /// If uri changed so that we have to change host or port, then we have to close socket stream
    /// 
    private void handleURLChange(in URI from, in URI to) {
        if ( _stream !is null && _stream.isConnected && 
            ( from.scheme != to.scheme || from.host != to.host || from.port != to.port) ) {
            debug tracef("Have to reopen stream, because of URI change");
            _stream.close();
        }
    }
    ///
    /// if we have new uri, then we need to check if we have to reopen existent connection
    /// 
    private void checkURL(string url, string file=__FILE__, size_t line=__LINE__) {
        if (url is null && _uri.uri == "" ) {
            throw new RequestException("No url configured", file, line);
        }
        
        if ( url !is null ) {
            URI newURI = URI(url);
            handleURLChange(_uri, newURI);
            _uri = newURI;
        }
    }
    ///
    /// Setup connection. Handle proxy and https case
    /// 
    private void setupConnection() {
        if ( !_stream || !_stream.isConnected ) {
            tracef("Set up new connection");
            URI   uri;
            if ( _proxy ) {
                // use proxy uri to connect
                uri.uri_parse(_proxy);
            } else {
                // use original uri
                uri = _uri;
            }
            final switch (uri.scheme) {
                case "http":
                    _stream = new TCPSocketStream().connect(uri.host, uri.port, _timeout);
                    break;
                case "https":
                    _stream = new SSLSocketStream().connect(uri.host, uri.port, _timeout);
                    break;
            }
        } else {
            tracef("Use old connection");
        }
    }
    ///
    /// Request sent, now receive response.
    /// Find headers, split on headers and body, continue to receive body
    /// 
    private void receiveResponse() {

        _stream.so.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, timeout);
        scope(exit) {
            _stream.so.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, 0.seconds);
        }

        _bodyDecoder = new DataPipe!ubyte();
        scope(exit) {
            if ( !_useStreaming ) {
                _bodyDecoder = null;
                _unChunker = null;
            }
        }

        auto buffer = Buffer!ubyte();
        Buffer!ubyte ResponseHeaders, partialBody;
        ptrdiff_t read;
        string separator;
        
        while(true) {

            auto b = new ubyte[_bufferSize];
            read = _stream.receive(b);

            debug tracef("read: %d", read);
            if ( read < 0 ) {
                version(Windows) {
                    if ( errno == 0 ) {
                        throw new TimeoutException("Timeout receiving headers");
                    }
                }
                version(Posix) {
                    if ( errno == EINTR ) {
                        continue;
                    }
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
            buffer.putNoCopy(data);
            if ( verbosity>=3 ) {
                writeln(data.dump.join("\n"));
            }

            if ( buffer.length > maxHeadersLength ) {
                throw new RequestException("Headers length > maxHeadersLength (%d > %d)".format(buffer.length, maxHeadersLength));
            }
            if ( headersHaveBeenReceived(data, buffer, separator) ) {
                auto s = buffer.data!(ubyte[]).findSplit(separator);
                ResponseHeaders = Buffer!ubyte(s[0]);
                partialBody = Buffer!ubyte(s[2]);
                _contentReceived += partialBody.length;
                parseResponseHeaders(ResponseHeaders);
                break;
            }
        }
        
        analyzeHeaders(_response._responseHeaders);

        _bodyDecoder.putNoCopy(partialBody.data);

        if ( _verbosity >= 2 ) {
            writefln("< %d bytes of body received", partialBody.length);
        }

        if ( _method == "HEAD" ) {
            // HEAD response have ContentLength, but have no body
            return;
        }

        while( true ) {
            if ( _contentLength >= 0 && _contentReceived >= _contentLength ) {
                debug trace("Body received.");
                break;
            }
            if ( _unChunker && _unChunker.done ) {
                break;
            }
            if ( _useStreaming && _response._responseBody.length && !redirectCodes.canFind(_response.code) ) {
                trace("streaming requested");
                _response.receiveAsRange.activated = true;
                _response.receiveAsRange.data = _response._responseBody.data;
                _response.receiveAsRange.read = delegate ubyte[] () {
                    while(true) {
                        // check if we received everything we need
                        if ( ( _unChunker && _unChunker.done )
                            || !_stream.isOpen() 
                            || (_contentLength > 0 && _contentReceived >= _contentLength) ) 
                        {
                            trace("streaming_in receive completed");
                            _bodyDecoder.flush();
                            return _bodyDecoder.get();
                        }
                        // have to continue
                        auto b = new ubyte[_bufferSize];
                        read = _stream.receive(b);
                        debug tracef("streaming_in received %d bytes", read);
                        if ( read < 0 ) {
                            version(Posix) {
                                if ( errno == EINTR ) {
                                    continue;
                                }
                            }
                            throw new RequestException("streaming_in error reading from socket");
                        }

                        if ( read == 0 ) {
                            debug tracef("streaming_in: server closed connection");
                            _bodyDecoder.flush();
                            return _bodyDecoder.get();
                        }

                        if ( verbosity>=3 ) {
                            writeln(b[0..read].dump.join("\n"));
                        }

                        _contentReceived += read;
                        _bodyDecoder.putNoCopy(b[0..read]);
                        auto res = _bodyDecoder.getNoCopy();
                        if ( res.length == 0 ) {
                            // there were nothing to produce (beginning of the chunk or no decompressed data)
                            continue;
                        }
                        //                        
                        // I'd like to "return _bodyDecoder.getNoCopy().join;" but if is slower
                        //
                        if (res.length == 1) {
                            return res[0];
                        }
                        auto total = res.map!(b=>b.length).sum;
                        // create buffer for joined bytes
                        ubyte[] joined = new ubyte[total];
                        size_t p;
                        // memcopy 
                        foreach(ref _; res) {
                            joined[p .. p + _.length] = _;
                            p += _.length;
                        }
                        return joined;
                    }
                    assert(0);
                };
                // we prepared for streaming
                return;
            }

            auto b = new ubyte[_bufferSize];
            read = _stream.receive(b);

            if ( read < 0 ) {
                version(Posix) {
                    if ( errno == EINTR ) {
                        continue;
                    }
                }
                if ( errno == EAGAIN ) {
                    throw new TimeoutException("Timeout receiving body");
                }
                throw new ErrnoException("receiving body");
            }
            if ( read == 0 ) {
                debug trace("read done");
                break;
            }
            if ( _verbosity >= 2 ) {
                writefln("< %d bytes of body received", read);
            }

            if ( verbosity>=3 ) {
                writeln(b[0..read].dump.join("\n"));
            }

            debug tracef("read: %d", read);
            _contentReceived += read;
            if ( _maxContentLength && _contentReceived > _maxContentLength ) {
                throw new RequestException("ContentLength > maxContentLength (%d>%d)".
                    format(_contentLength, _maxContentLength));
            }

            _bodyDecoder.putNoCopy(b[0..read]); // send buffer to all decoders

            _bodyDecoder.getNoCopy.             // fetch result and place to body
                each!(b => _response._responseBody.putNoCopy(b));

            debug tracef("receivedTotal: %d, contentLength: %d, bodyLength: %d", _contentReceived, _contentLength, _response._responseBody.length);

        }
        _bodyDecoder.flush();
        _response._responseBody.putNoCopy(_bodyDecoder.get());
    }
    private bool serverClosedKeepAliveConnection() pure @safe nothrow {
        return _response._responseHeaders.length == 0 && _keepAlive;
    }
    private bool isIdempotent(in string method) pure @safe nothrow {
        return ["GET", "HEAD"].canFind(method);
    }
    ///
    /// Send multipart for request.
    /// You would like to use this method for sending large portions of mixed data or uploading files to forms.
    /// Content of the posted form consist of sources. Each source have at least name and value (can be string-like object or opened file, see more docs for MultipartForm struct)
    /// Params:
    ///     url = url
    ///     sources = array of sources.
    HTTPResponse exec(string method="POST")(string url, MultipartForm sources) {
        import std.uuid;
        import std.file;
        //
        // application/json
        //
        bool restartedRequest = false;
        
        _method = method;
        
        _response = new HTTPResponse;
        checkURL(url);
        _response.uri = _uri;
        _response.finalURI = _uri;

    connect:
        _contentReceived = 0;
        _response._startedAt = Clock.currTime;
        setupConnection();
        
        if ( !_stream.isConnected() ) {
            return _response;
        }
        _response._connectedAt = Clock.currTime;
        
        Appender!string req;
        req.put(requestString());
        
        string   boundary = randomUUID().toString;
        string[] partHeaders;
        size_t   contentLength;
        
        foreach(ref part; sources._sources) {
            string h = "--" ~ boundary ~ "\r\n";
            string disposition = "form-data; name=%s".format(part.name);
            string optionals = part.
                parameters.byKeyValue().
                filter!(p => p.key!="Content-Type").
                map!   (p => "%s=%s".format(p.key, p.value)).
                join("; ");

            h ~= `Content-Disposition: ` ~ [disposition, optionals].join("; ") ~ "\r\n";

            auto contentType = "Content-Type" in part.parameters;
            if ( contentType ) {
                h ~= "Content-Type: " ~ *contentType ~ "\r\n";
            }

            h ~= "\r\n";
            partHeaders ~= h;
            contentLength += h.length + part.input.getSize() + "\r\n".length;
        }
        contentLength += "--".length + boundary.length + "--\r\n".length;
        
        auto h = requestHeaders();
        h["Content-Type"] = "multipart/form-data; boundary=" ~ boundary;
        h["Content-Length"] = to!string(contentLength);
        h.byKeyValue.
            map!(kv => kv.key ~ ": " ~ kv.value ~ "\r\n").
                each!(h => req.put(h));
        req.put("\r\n");
        
        trace(req.data);
        if ( _verbosity >= 1 ) {
            req.data.splitLines.each!(a => writeln("> " ~ a));
        }
        
        auto rc = _stream.send(req.data());
        if ( rc == -1 ) {
            errorf("Error sending request: ", lastSocketError);
            return _response;
        }
        foreach(ref source; sources._sources) {
            auto hdr = partHeaders.front;
            partHeaders.popFront;
            tracef("sending part headers <%s>", hdr);
            _stream.send(hdr);
            while (true) {
                auto chunk = source.input.read();
                if ( chunk.length <= 0 ) {
                    break;
                }
                _stream.send(chunk);
            }
            _stream.send("\r\n");
        }
        _stream.send("--" ~ boundary ~ "--\r\n");
        _response._requestSentAt = Clock.currTime;
        
        receiveResponse();
        
        if ( _useStreaming ) {
            if ( _response._receiveAsRange.activated ) {
                trace("streaming_in activated");
                return _response;
            } else {
                _response._receiveAsRange.data = _response.responseBody.data;
            }
        }

        if ( serverClosedKeepAliveConnection()
            && !restartedRequest
            && isIdempotent(_method)
            ) {
            tracef("Server closed keepalive connection");
            _stream.close();
            restartedRequest = true;
            goto connect;
        }
        
        _response._finishedAt = Clock.currTime;
        ///
        auto connection = "connection" in _response._responseHeaders;
        if ( !connection || *connection == "close" ) {
            tracef("Closing connection because of 'Connection: close' or no 'Connection' header");
            _stream.close();
        }
        if ( canFind(redirectCodes, _response.code) && followRedirectResponse() ) {
            if ( _method != "GET" ) {
                return this.get();
            }
            goto connect;
        }
        _response._history = _history;
        ///
        return _response;
    }
    ///
    /// POST/PUT/... data from some string(with Content-Length), or from range of strings/bytes (use Transfer-Encoding: chunked).
    /// When rank 1 (flat array) used as content it must have length. In that case "content" will be sent directly to network, and Content-Length headers will be added.
    /// If you are goung to send some range and do not know length at the moment when you start to send request, then you can send chunks of chars or ubyte.
    /// Try not to send too short chunks as this will put additional load on client and server. Chunks of length 2048 or 4096 are ok.
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
        if ( (rank!R == 1)
            || (rank!R == 2 && isSomeChar!(Unqual!(typeof(content.front.front)))) 
            || (rank!R == 2 && (is(Unqual!(typeof(content.front.front)) == ubyte)))
        ) {
        //
        // application/json
        //
        bool restartedRequest = false;

        _method = method;
        
        _response = new HTTPResponse;
        checkURL(url);
        _response.uri = _uri;
        _response.finalURI = _uri;

    connect:
        _contentReceived = 0;
        _response._startedAt = Clock.currTime;
        setupConnection();
        
        if ( !_stream.isConnected() ) {
            return _response;
        }
        _response._connectedAt = Clock.currTime;

        Appender!string req;
        req.put(requestString());

        auto h = requestHeaders;
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

        debug trace(req.data);
        if ( _verbosity >= 1 ) {
            req.data.splitLines.each!(a => writeln("> " ~ a));
        }

        auto rc = _stream.send(req.data());
        if ( rc == -1 ) {
            errorf("Error sending request: ", lastSocketError);
            return _response;
        }

        static if ( rank!R == 1) {
            _stream.send(content);
        } else {
            while ( !content.empty ) {
                auto chunk = content.front;
                auto chunkHeader = "%x\r\n".format(chunk.length);
                debug tracef("sending %s%s", chunkHeader, chunk);
                _stream.send(chunkHeader);
                _stream.send(chunk);
                _stream.send("\r\n");
                content.popFront;
            }
            tracef("sent");
            _stream.send("0\r\n\r\n");
        }
        _response._requestSentAt = Clock.currTime;

        receiveResponse();

        if ( _useStreaming ) {
            if ( _response._receiveAsRange.activated ) {
                debug trace("streaming_in activated");
                return _response;
            } else {
                _response._receiveAsRange.data = _response.responseBody.data;
            }
        }

        if ( serverClosedKeepAliveConnection()
            && !restartedRequest
            && isIdempotent(_method)
        ) {
            debug tracef("Server closed keepalive connection");
            _stream.close();
            restartedRequest = true;
            goto connect;
        }

        _response._finishedAt = Clock.currTime;

        ///
        auto connection = "connection" in _response._responseHeaders;
        if ( !connection || *connection == "close" ) {
            tracef("Closing connection because of 'Connection: close' or no 'Connection' header");
            _stream.close();
        }
        if ( canFind(redirectCodes, _response.code) && followRedirectResponse() ) {
            if ( _method != "GET" ) {
                return this.get();
            }
            goto connect;
        }
        ///
        _response._history = _history;
        return _response;
    }
    ///
    /// Send request with pameters.
    /// If used for POST or PUT requests then application/x-www-form-urlencoded used.
    /// Request parameters will be encoded into request string or placed in request body for POST/PUT
    /// requests.
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
    HTTPResponse exec(string method="GET")(string url = null, QueryParam[] params = null) {

        _method = method;
        _response = new HTTPResponse;
        _history.length = 0;
        bool restartedRequest = false; // True if this is restarted keepAlive request
        string encoded;

        checkURL(url);
        _response.uri = _uri;
        _response.finalURI = _uri;

    connect:
        _contentReceived = 0;
        _response._startedAt = Clock.currTime;
        setupConnection();

        if ( !_stream.isConnected() ) {
            return _response;
        }
        _response._connectedAt = Clock.currTime;

        auto h = requestHeaders();

        Appender!string req;

        if ( ["POST", "PUT"].canFind(_method) && params ) {
            encoded = params2query(params);
            h["Content-Type"] = "application/x-www-form-urlencoded";
            h["Content-Length"] = to!string(encoded.length);
            req.put(requestString());
        } else {
            req.put(requestString(params));
        }

        h.byKeyValue.
            map!(kv => kv.key ~ ": " ~ kv.value ~ "\r\n").
            each!(h => req.put(h));
        req.put("\r\n");
        if ( encoded ) {
            req.put(encoded);
        }

        trace(req.data);

        if ( _verbosity >= 1 ) {
            req.data.splitLines.each!(a => writeln("> " ~ a));
        }
        auto rc = _stream.send(req.data());
        if ( rc == -1 ) {
            errorf("Error sending request: ", lastSocketError);
            return _response;
        }
        _response._requestSentAt = Clock.currTime;

        receiveResponse();

        if ( _useStreaming ) {
            if ( _response._receiveAsRange.activated ) {
                trace("streaming_in activated");
                return _response;
            } else {
                _response._receiveAsRange.data = _response.responseBody.data;
            }
        }
        if ( serverClosedKeepAliveConnection()
            && !restartedRequest
            && isIdempotent(_method)
        ) {
            tracef("Server closed keepalive connection");
            _stream.close();
            restartedRequest = true;
            goto connect;
        }

        _response._finishedAt = Clock.currTime;

        ///
        auto connection = "connection" in _response._responseHeaders;
        if ( !connection || *connection == "close" ) {
            tracef("Closing connection because of 'Connection: close' or no 'Connection' header");
            _stream.close();
        }
        if ( _verbosity >= 1 ) {
            writeln(">> Connect time: ", _response._connectedAt - _response._startedAt);
            writeln(">> Request send time: ", _response._requestSentAt - _response._connectedAt);
            writeln(">> Response recv time: ", _response._finishedAt - _response._requestSentAt);
        }
        if ( canFind(redirectCodes, _response.code) && followRedirectResponse() ) {
            if ( _method != "GET" ) {
                return this.get();
            }
            goto connect;
        }
        ///
        _response._history = _history;
        return _response;
    }

    /// WRAPPERS
    ///
    /// send file(s) using POST and multipart form.
    /// This wrapper will be deprecated, use post with MultipartForm - it is more general and clear.
    /// Parameters:
    ///     url = url
    ///     files = array of PostFile structures
    /// Returns:
    ///     Response
    /// Each PostFile structure contain path to file, and optional field name and content type.
    /// If no field name provided, then basename of the file will be used.
    /// application/octet-stream is default when no content type provided.
    /// Example:
    /// ---------------------------------------------------------------
    ///    PostFile[] files = [
    ///                   {fileName:"tests/abc.txt", fieldName:"abc", contentType:"application/octet-stream"}, 
    ///                   {fileName:"tests/test.txt"}
    ///               ];
    ///    rs = rq.exec!"POST"("http://httpbin.org/post", files);
    /// ---------------------------------------------------------------
    /// 
    HTTPResponse exec(string method="POST")(string url, PostFile[] files) if (method=="POST") {
        MultipartForm multipart;
        File[]        toClose;
        foreach(ref f; files) {
            File file = File(f.fileName, "rb");
            toClose ~= file;
            string fileName = f.fileName ? f.fileName : f.fieldName;
            string contentType = f.contentType ? f.contentType : "application/octetstream";
            multipart.add(f.fieldName, new FormDataFile(file), ["filename":fileName, "Content-Type": contentType]);
        }
        auto res = exec!"POST"(url, multipart);
        toClose.each!"a.close";
        return res;
    }
    ///
    /// exec request with parameters when you can use dictionary (when you have no duplicates in parameter names)
    /// Consider switch to exec(url, QueryParams) as it more generic and clear.
    /// Parameters:
    ///     url = url
    ///     params = dictionary with field names as keys and field values as values.
    /// Returns:
    ///     Response
    HTTPResponse exec(string method="GET")(string url, string[string] params) {
        return exec!method(url, params.byKeyValue.map!(p => QueryParam(p.key, p.value)).array);
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
    /// uri = endpoint uri
    /// args = request parameters. see exec docs.
    ///
    HTTPResponse post(A...)(string uri, A args) {
        return exec!"POST"(uri, args);
    }
}

///
package unittest {
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
    {
        info("Check POST from AA");
        rs = rq.post("http://httpbin.org/post", ["a":"b", "c":"d"]);
        assert(rs.code==200);
        auto data = parseJSON(rs.responseBody.data).object["form"].object;
        assert(data["a"].str == "b");
        assert(data["c"].str == "d");
    }
    {
        info("Check POST from QueryParams");
        rs = rq.post("http://httpbin.org/post", queryParams("name[]", "first", "name[]", 2));
        assert(rs.code==200);
        auto data = parseJSON(rs.responseBody.data).object["form"].object;
        assert((data["name[]"].array[0].str == "first"));
        assert((data["name[]"].array[1].str == "2"));
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
    //rq.verbosity = 3;
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
    assertThrown!MaxRedirectsException(rq.get("https://httpbin.org/absolute-redirect/3"));
    info("Check utf8 content");
    globalLogLevel(LogLevel.info);
    rq = HTTPRequest();
    rs = rq.get("http://httpbin.org/encoding/utf8");
    assert(rs.code==200);

    info("Check cookie");
    rs = HTTPRequest().get("http://httpbin.org/cookies/set?A=abcd&b=cdef");
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

    info("Check chunked content");
    globalLogLevel(LogLevel.info);
    rq = HTTPRequest();
    rq.keepAlive = true;
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
//    assertThrown!ConnectError(rq.get("http://0.0.0.0:65000/"));
//    assertThrown!ConnectError(rq.get("http://1.1.1.1/"));
    //assertThrown!ConnectError(rq.get("http://gkhgkhgkjhgjhgfjhgfjhgf/"));

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
