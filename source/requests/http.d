module requests.http;

private:
import std.algorithm;
import std.array;
import std.ascii;
import std.conv;
import std.datetime;
import std.exception;
import std.format;
import std.stdio;
import std.range;
import std.string;
import std.traits;
import std.typecons;
import std.bitmanip;
import std.experimental.logger;
import core.thread;

import requests.streams;
import requests.uri;
import requests.utils;
import requests.base;

static immutable ushort[] redirectCodes = [301, 302, 303, 307, 308];
static immutable uint     defaultBufferSize = 12*1024;

static immutable string[string] proxies;
static this() {
    import std.process;
    proxies["http"] = environment.get("http_proxy", environment.get("HTTP_PROXY"));
    proxies["https"] = environment.get("https_proxy", environment.get("HTTPS_PROXY"));
    proxies["all"] = environment.get("all_proxy", environment.get("ALL_PROXY"));
    foreach(p; proxies.byKey()) {
        if (proxies[p] is null) {
            continue;
        }
        URI u = URI(proxies[p]);
    }
}

public class MaxRedirectsException: Exception {
    this(string message, string file = __FILE__, size_t line = __LINE__, Throwable next = null) @safe pure nothrow {
        super(message, file, line, next);
    }
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
    override string userName() {
        return _username;
    }
    override string password() {
        return _password;
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
        struct _UH {
            // flags for each important header, added by user using addHeaders
            mixin(bitfields!(
                bool, "Host", 1,
                bool, "UserAgent", 1,
                bool, "ContentLength", 1,
                bool, "Connection", 1,
                bool, "AcceptEncoding", 1,
                bool, "ContentType", 1,
                bool, "Cookie", 1,
                uint, "", 1
            ));
        }
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

        NetworkStream   _stream;
        HTTPResponse[] _history; // redirects history
        DataPipe!ubyte _bodyDecoder;
        DecodeChunked  _unChunker;
        long           _contentLength;
        long           _contentReceived;
        Cookie[]       _cookie;
        SSLOptions     _sslOptions;
        string         _bind;
        _UH            _userHeaders;
    }
    package HTTPResponse   _response;

    mixin(Getter_Setter!string     ("method"));
    mixin(Getter_Setter!bool       ("keepAlive"));
    mixin(Getter_Setter!size_t     ("maxContentLength"));
    mixin(Getter_Setter!size_t     ("maxHeadersLength"));
    mixin(Getter_Setter!size_t     ("bufferSize"));
    mixin(Getter_Setter!uint       ("maxRedirects"));
    mixin(Getter_Setter!uint       ("verbosity"));
    mixin(Getter!string            ("proxy"));
    mixin(Getter_Setter!Duration   ("timeout"));
    mixin(Setter!Auth              ("authenticator"));
    mixin(Getter_Setter!bool       ("useStreaming"));
    mixin(Getter!long              ("contentLength"));
    mixin(Getter!long              ("contentReceived"));
    mixin(Getter_Setter!SSLOptions ("sslOptions"));
    mixin(Getter_Setter!string     ("bind"));

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
    @property final void cookie(Cookie[] s) pure @safe @nogc nothrow {
        _cookie = s;
    }
    @property final void proxy(string v) {
        if ( v != _proxy ) {
            if ( _stream && _stream.isOpen() ) {
                debug(requests) tracef("Close connection because we reset proxy");
                _stream.close();
            }
        }
        _proxy = v;
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
    string toString() const {
        return "HTTPRequest(%s, %s)".format(_method, _uri.uri());
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
    string select_proxy(string scheme) {
        if ( _proxy is null && proxies.length == 0 ) {
            debug(requests) tracef("proxy=null");
            return null;
        }
        if ( _proxy ) {
            debug(requests) tracef("proxy=%s", _proxy);
            return _proxy;
        }
        auto p = scheme in proxies;
        if ( p !is null && *p != "") {
            debug(requests) tracef("proxy=%s", *p);
            return *p;
        }
        p = "all" in proxies;
        if ( p !is null && *p != "") {
            debug(requests) tracef("proxy=%s", *p);
            return *p;
        }
        debug(requests) tracef("proxy=null");
        return null;
    }
    void clearHeaders() {
        _headers = null;
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
    private void safeSetHeader(ref string[string] headers, bool userAdded, string h, string v) pure @safe {
        if ( !userAdded ) {
            headers[h] = v;
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

        string[string] generatedHeaders;

        if ( _authenticator ) {
            _authenticator.
                authHeaders(_uri.host).
                byKeyValue.
                each!(pair => generatedHeaders[pair.key] = pair.value);
        }

        _headers.byKey.each!(h => generatedHeaders[h] = _headers[h]);

        safeSetHeader(generatedHeaders, _userHeaders.AcceptEncoding, "Accept-Encoding", "gzip,deflate");
        safeSetHeader(generatedHeaders, _userHeaders.UserAgent, "User-Agent", "dlang-requests");
        safeSetHeader(generatedHeaders, _userHeaders.Connection, "Connection", _keepAlive?"Keep-Alive":"Close");

        if ( !_userHeaders.Host )
        {
            generatedHeaders["Host"] = _uri.host;
            if ( _uri.scheme !in standard_ports || _uri.port != standard_ports[_uri.scheme] ) {
                generatedHeaders["Host"] ~= ":%d".format(_uri.port);
            }
        }

        if ( _cookie.length && !_userHeaders.Cookie ) {
            auto cs = _cookie.
                filter!(c => _uri.path.pathMatches(c.path) && _uri.host.domainMatches(c.domain)).
                map!(c => "%s=%s".format(c.attr, c.value)).
                joiner(";");
            if ( ! cs.empty )
            {
                generatedHeaders["Cookie"] = to!string(cs);
            }
        }

        _filteredHeaders.each!(h => generatedHeaders.remove(h));

        return generatedHeaders;
    }
    ///
    /// Build request string.
    /// Handle proxy and query parameters.
    ///
    private @property string requestString(QueryParam[] params = null) {
        string actual_proxy = select_proxy(_uri.scheme);
        if ( actual_proxy && _uri.scheme != "https" ) {
            return "%s %s HTTP/1.1\r\n".format(_method, _uri.uri);
        }
        auto query = _uri.query.dup;
        if ( params ) {
            query ~= "&" ~ params2query(params);
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
            debug(requests) tracef("transferEncoding: %s", *transferEncoding);
            if ( (*transferEncoding).toLower == "chunked") {
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
    private void parseResponseHeaders(in ubyte[] input) {
        string lastHeader;
        auto buffer = cast(string)input;

        foreach(line; buffer.split("\n").map!(l => l.stripRight)) {
            if ( ! _response.status_line.length ) {
                debug (requests) tracef("statusLine: %s", line);
                _response.status_line = line;
                if ( _verbosity >= 1 ) {
                    writefln("< %s", line);
                }
                auto parsed = line.split(" ");
                if ( parsed.length >= 2 ) {
                    _response.code = parsed[1].to!ushort;
                }
                continue;
            }
            if ( line[0] == ' ' || line[0] == '\t' ) {
                // unfolding https://tools.ietf.org/html/rfc822#section-3.1
                if ( auto stored = lastHeader in _response._responseHeaders) {
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
            debug (requests) tracef("Header %s = %s", header, value);

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
            debug(requests) tracef("Closing connection because of 'Connection: close' or no 'Connection' header");
            _stream.close();
        }
        URI oldURI = _uri;
        URI newURI = oldURI;
        try {
            newURI = URI(*location);
        } catch (UriException e) {
            debug(requests) trace("Can't parse Location:, try relative uri");
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
    /// If uri changed so that we have to change host, port or proxy, then we have to close socket stream
    ///
    private void handleURLChange(in URI from, in URI to) {
        if ( _stream is null || !_stream.isConnected ) {
            return;
        }
        string proxy_from = select_proxy(from.scheme);
        string proxy_to = select_proxy(to.scheme);
        if ( proxy_from != proxy_to ) {
            // we are switching proxies
            _stream.close();
            return;
        }
        if ( proxy_to !is null ) {
            // we do not have to close proxy connection if we will not change proxy
            if ( (from.scheme=="https" || to.scheme=="https")
                 && (from.scheme != to.scheme) ) {
                _stream.close();
            }
            return;
        }
        if ( from.scheme != to.scheme || from.host != to.host || from.port != to.port ) {
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
        if ( _stream && _stream.isConnected ) {
            debug(requests) tracef("Use old connection");
            return;
        }

        debug(requests) tracef("Set up new connection");

        URI   uri; // this URI will be used temporarry if we need proxy
        string actual_proxy = select_proxy(_uri.scheme);
        final switch (_uri.scheme) {
            case "http":
                if ( actual_proxy ) {
                    uri.uri_parse(actual_proxy);
                    uri.idn_encode();
                } else {
                    // use original uri
                    uri = _uri;
                }
                _stream = new TCPStream();
                _stream.bind(_bind);
                _stream.connect(uri.host, uri.port, _timeout);
                break;
            case "https":
                if ( actual_proxy ) {
                    uri.uri_parse(actual_proxy);
                    uri.idn_encode();
                    _stream = new TCPStream();
                    _stream.bind(_bind);
                    _stream.connect(uri.host, uri.port, _timeout);
                    if ( verbosity>=1 ) {
                        writeln("> CONNECT %s:%d HTTP/1.1".format(_uri.host, _uri.port));
                    }
                    _stream.send("CONNECT %s:%d HTTP/1.1\r\n\r\n".format(_uri.host, _uri.port));
                    while ( _stream.isConnected ) {
                        ubyte[1024] b;
                        auto read = _stream.receive(b);
                        if ( verbosity>=1) {
                            writefln("< %s", cast(string)b[0..read]);
                        }
                        debug(requests) tracef("read: %d", read);
                        if ( b[0..read].canFind("\r\n\r\n") || b[0..read].canFind("\n\n") ) {
                            debug(requests) tracef("proxy connection ready");
                            // convert connection to ssl
                            _stream = new SSLStream(_stream, _sslOptions, _uri.host);
                            break;
                        } else {
                            debug(requests) tracef("still wait for proxy connection");
                        }
                    }
                } else {
                    uri = _uri;
                    _stream = new SSLStream(_sslOptions);
                    _stream.bind(_bind);
                    _stream.connect(uri.host, uri.port, _timeout);
                    debug(requests) tracef("ssl connection to origin server ready");
                }
                break;
        }
    }
    ///
    /// Request sent, now receive response.
    /// Find headers, split on headers and body, continue to receive body
    ///
    private void receiveResponse() {

        _stream.readTimeout = timeout;
        scope(exit) {
            if ( _stream && _stream.isOpen ) {
                _stream.readTimeout = 0.seconds;
            }
        }

        _bodyDecoder = new DataPipe!ubyte();
        scope(exit) {
            if ( !_useStreaming ) {
                _bodyDecoder = null;
                _unChunker = null;
            }
        }

        auto buffer = Buffer!ubyte();
        Buffer!ubyte partialBody;
        ptrdiff_t read;
        string separator;

        while(true) {

            auto b = new ubyte[_bufferSize];
            read = _stream.receive(b);

            debug(requests) tracef("read: %d", read);
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
                auto s = buffer.data.findSplit(separator);
                auto ResponseHeaders = s[0];
                partialBody = Buffer!ubyte(s[2]);
                _contentReceived += partialBody.length;
                parseResponseHeaders(ResponseHeaders);
                break;
            }
        }

        analyzeHeaders(_response._responseHeaders);

        _bodyDecoder.putNoCopy(partialBody.data);

        auto v = _bodyDecoder.get();
        _response._responseBody.putNoCopy(v);

        if ( _verbosity >= 2 ) writefln("< %d bytes of body received", partialBody.length);

        if ( _method == "HEAD" ) {
            // HEAD response have ContentLength, but have no body
            return;
        }

        while( true ) {
            if ( _contentLength >= 0 && _contentReceived >= _contentLength ) {
                debug(requests) trace("Body received.");
                break;
            }
            if ( _unChunker && _unChunker.done ) {
                break;
            }

            if ( _useStreaming && _response._responseBody.length && !redirectCodes.canFind(_response.code) ) {
                debug(requests) trace("streaming requested");
                _response.receiveAsRange.activated = true;
                _response.receiveAsRange.data = _response._responseBody.data;
                _response.receiveAsRange.read = delegate ubyte[] () {
                    while(true) {
                        // check if we received everything we need
                        if ( ( _unChunker && _unChunker.done )
                            || !_stream.isConnected()
                            || (_contentLength > 0 && _contentReceived >= _contentLength) )
                        {
                            debug(requests) trace("streaming_in receive completed");
                            _bodyDecoder.flush();
                            return _bodyDecoder.get();
                        }
                        // have to continue
                        auto b = new ubyte[_bufferSize];
                        try {
                            read = _stream.receive(b);
                        }
                        catch (Exception e) {
                            throw new RequestException("streaming_in error reading from socket", __FILE__, __LINE__, e);
                        }
                        debug(requests) tracef("streaming_in received %d bytes", read);

                        if ( read == 0 ) {
                            debug(requests) tracef("streaming_in: server closed connection");
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
                        if (res.length == 1) {
                            return res[0];
                        }
                        //
                        // I'd like to "return _bodyDecoder.getNoCopy().join;" but it is slower
                        //
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

            if ( read == 0 ) {
                debug(requests) trace("read done");
                break;
            }
            if ( _verbosity >= 2 ) {
                writefln("< %d bytes of body received", read);
            }

            if ( verbosity>=3 ) {
                writeln(b[0..read].dump.join("\n"));
            }

            debug(requests) tracef("read: %d", read);
            _contentReceived += read;
            if ( _maxContentLength && _contentReceived > _maxContentLength ) {
                throw new RequestException("ContentLength > maxContentLength (%d>%d)".
                    format(_contentLength, _maxContentLength));
            }

            _bodyDecoder.putNoCopy(b[0..read]); // send buffer to all decoders

            _bodyDecoder.getNoCopy.             // fetch result and place to body
                each!(b => _response._responseBody.putNoCopy(b));

            debug(requests) tracef("receivedTotal: %d, contentLength: %d, bodyLength: %d", _contentReceived, _contentLength, _response._responseBody.length);

        }
        _bodyDecoder.flush();
        _response._responseBody.putNoCopy(_bodyDecoder.get());
    }
    private bool serverClosedKeepAliveConnection() pure @safe nothrow {
        return _response._responseHeaders.length == 0 && _response._status_line.length == 0 &&  _keepAlive;
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

        if ( _response && _response._receiveAsRange.activated && _stream && _stream.isConnected ) {
            _stream.close();
        }
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
            string disposition = `form-data; name="%s"`.format(part.name);
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
        safeSetHeader(h, _userHeaders.ContentType, "Content-Type", "multipart/form-data; boundary=" ~ boundary);
        safeSetHeader(h, _userHeaders.ContentLength, "Content-Length", to!string(contentLength));
        
        h.byKeyValue.
            map!(kv => kv.key ~ ": " ~ kv.value ~ "\r\n").
                each!(h => req.put(h));
        req.put("\r\n");

        debug(requests) trace(req.data);
        if ( _verbosity >= 1 ) req.data.splitLines.each!(a => writeln("> " ~ a));

        try {
            _stream.send(req.data());
            foreach(ref source; sources._sources) {
                debug(requests) tracef("sending part headers <%s>", partHeaders.front);
                _stream.send(partHeaders.front);
                partHeaders.popFront;
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
            _response._finishedAt = Clock.currTime;
        }
        catch (NetworkException e) {
            errorf("Error sending request: ", e.msg);
            return _response;
        }
        if ( _useStreaming ) {
            if ( _response._receiveAsRange.activated ) {
                debug(requests) trace("streaming_in activated");
                return _response;
            } else {
                _response._receiveAsRange.data = _response.responseBody.data;
            }
        }
        auto connection = "connection" in _response._responseHeaders;
        if ( !connection || *connection == "close" ) {
            debug(requests) tracef("Closing connection because of 'Connection: close' or no 'Connection' header");
            _stream.close();
        }
        if ( canFind(redirectCodes, _response.code) && followRedirectResponse() ) {
            if ( _method != "GET" && _response.code != 307 && _response.code != 308 ) {
                // 307 and 308 do not change method
                return this.get();
            }
            goto connect;
        }
        _response._history = _history;
        ///
        return _response;
    }

    // we use this if we send from ubyte[][] and user provided Content-Length
    private void sendFlattenContent(T)(NetworkStream _stream, T content) {
        while ( !content.empty ) {
            auto chunk = content.front;
            _stream.send(chunk);
            content.popFront;
        }
        debug(requests) tracef("sent");
    }
    // we use this if we send from ubyte[][] as chunked content
    private void sendChunkedContent(T)(NetworkStream _stream, T content) {
        while ( !content.empty ) {
            auto chunk = content.front;
            auto chunkHeader = "%x\r\n".format(chunk.length);
            debug(requests) tracef("sending %s%s", chunkHeader, chunk);
            _stream.send(chunkHeader);
            _stream.send(chunk);
            _stream.send("\r\n");
            content.popFront;
        }
        debug(requests) tracef("sent");
        _stream.send("0\r\n\r\n");
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
    HTTPResponse exec(string method="POST", R)(string url, R content, string contentType="application/octet-stream")
        if ( (rank!R == 1)
            || (rank!R == 2 && isSomeChar!(Unqual!(typeof(content.front.front))))
            || (rank!R == 2 && (is(Unqual!(typeof(content.front.front)) == ubyte)))
        ) {
        if ( _response && _response._receiveAsRange.activated && _stream && _stream.isConnected ) {
            _stream.close();
        }
        //
        // application/json
        //
        bool restartedRequest = false;
        bool send_flat;

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
        if ( contentType ) {
            safeSetHeader(h, _userHeaders.ContentType, "Content-Type", contentType);
        }
        static if ( rank!R == 1 ) {
            safeSetHeader(h, _userHeaders.ContentLength, "Content-Length", to!string(content.length));
        } else {
            if ( _userHeaders.ContentLength ) {
                debug(requests) tracef("User provided content-length for chunked content");
                send_flat = true;
            } else {
                h["Transfer-Encoding"] = "chunked";
                send_flat = false;
            }
        }
        h.byKeyValue.
            map!(kv => kv.key ~ ": " ~ kv.value ~ "\r\n").
            each!(h => req.put(h));
        req.put("\r\n");

        debug(requests) trace(req.data);
        if ( _verbosity >= 1 ) {
            req.data.splitLines.each!(a => writeln("> " ~ a));
        }

        try {
            // send headers
            _stream.send(req.data());
            // send body
            static if ( rank!R == 1) {
                _stream.send(content);
            } else {
                if ( send_flat ) {
                    sendFlattenContent(_stream, content);
                } else {
                    sendChunkedContent(_stream, content);
                }
            }
            _response._requestSentAt = Clock.currTime;
            receiveResponse();
            _response._finishedAt = Clock.currTime;
        } catch (NetworkException e) {
            _stream.close();
            throw new RequestException("Network error during data exchange");
        }

        if ( _useStreaming ) {
            if ( _response._receiveAsRange.activated ) {
                debug(requests) trace("streaming_in activated");
                return _response;
            } else {
                _response._receiveAsRange.data = _response.responseBody.data;
            }
        }
        auto connection = "connection" in _response._responseHeaders;
        if ( !connection || *connection == "close" ) {
            debug(requests) tracef("Closing connection because of 'Connection: close' or no 'Connection' header");
            _stream.close();
        }
        if ( canFind(redirectCodes, _response.code) && followRedirectResponse() ) {
            if ( _method != "GET" && _response.code != 307 && _response.code != 308 ) {
                // 307 and 308 do not change method
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

        if ( _response && _response._receiveAsRange.activated && _stream && _stream.isConnected ) {
            _stream.close();
        }
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

        switch (_method) {
            case "POST","PUT":
                encoded = params2query(params);
                safeSetHeader(h, _userHeaders.ContentType, "Content-Type", "application/x-www-form-urlencoded");
                if ( encoded.length > 0) {
                    safeSetHeader(h, _userHeaders.ContentLength, "Content-Length", to!string(encoded.length));
                }
                req.put(requestString());
                break;
            default:
                req.put(requestString(params));
        }

        h.byKeyValue.
            map!(kv => kv.key ~ ": " ~ kv.value ~ "\r\n").
            each!(h => req.put(h));
        req.put("\r\n");
        if ( encoded ) {
            req.put(encoded);
        }

        debug(requests) trace(req.data);

        if ( _verbosity >= 1 ) req.data.splitLines.each!(a => writeln("> " ~ a));
        //
        // Now send request and receive response
        //
        try {
            _stream.send(req.data());
            _response._requestSentAt = Clock.currTime;
            receiveResponse();
            _response._finishedAt = Clock.currTime;
        }
        catch (NetworkException e) {
            // On SEND this can means:
            // we started to send request to the server, but it closed connection because of keepalive timeout.
            // We have to restart request if possible.

            // On RECEIVE - if we received something - then this exception is real and unexpected error.
            // If we didn't receive anything - we can restart request again as it can be
            if ( _response._responseHeaders.length != 0 ) {
                _stream.close();
                throw new RequestException("Unexpected network error");
            }
        }

        if ( serverClosedKeepAliveConnection()
            && !restartedRequest
            && isIdempotent(_method)
            ) {
            ///
            /// We didn't receive any data (keepalive connectioin closed?)
            /// and we can restart this request.
            /// Go ahead.
            ///
            debug(requests) tracef("Server closed keepalive connection");
            _stream.close();
            restartedRequest = true;
            goto connect;
        }

        if ( _useStreaming ) {
            if ( _response._receiveAsRange.activated ) {
                debug(requests) trace("streaming_in activated");
                return _response;
            } else {
                // this can happen if whole response body received together with headers
                _response._receiveAsRange.data = _response.responseBody.data;
            }
        }

        auto connection = "connection" in _response._responseHeaders;
        if ( !connection || *connection == "close" ) {
            debug(requests) tracef("Closing connection because of 'Connection: close' or no 'Connection' header");
            _stream.close();
        }
        if ( _verbosity >= 1 ) {
            writeln(">> Connect time: ", _response._connectedAt - _response._startedAt);
            writeln(">> Request send time: ", _response._requestSentAt - _response._connectedAt);
            writeln(">> Response recv time: ", _response._finishedAt - _response._requestSentAt);
        }
        if ( canFind(redirectCodes, _response.code) && followRedirectResponse() ) {
            if ( _method != "GET" && _response.code != 307 && _response.code != 308 ) {
                // 307 and 308 do not change method
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

version(vibeD) {
    import std.json;
    package string httpTestServer() {
        return "http://httpbin.org/";
    }
    package string fromJsonArrayToStr(JSONValue v) {
        return v.str;
    }
}
else {
    import std.json;
    package string httpTestServer() {
        return "http://127.0.0.1:8081/";
    }
    package string fromJsonArrayToStr(JSONValue v) {
        return cast(string)(v.array.map!"cast(ubyte)a.integer".array);
    }
}


package unittest {
    import std.json;
    import std.array;

    globalLogLevel(LogLevel.info);

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
    HTTPRequest  rq;
    HTTPResponse rs;
    info("Check GET");
    URI uri = URI(httpbinUrl);
    rs = rq.get(httpbinUrl);
    assert(rs.code==200);
    assert(rs.responseBody.length > 0);
    assert(rq.format("%m|%h|%p|%P|%q|%U") ==
            "GET|%s|%d|%s||%s"
            .format(uri.host, uri.port, uri.path, httpbinUrl));
    info("Check GET with AA params");
    {
        rs = HTTPRequest().get(httpbinUrl ~ "get", ["c":" d", "a":"b"]);
        assert(rs.code == 200);
        auto json = parseJSON(cast(string)rs.responseBody.data).object["args"].object;
        assert(json["c"].str == " d");
        assert(json["a"].str == "b");
    }
    info("Check POST files");
    {
        import std.file;
        import std.path;
        auto tmpd = tempDir();
        auto tmpfname = tmpd ~ dirSeparator ~ "request_test.txt";
        auto f = File(tmpfname, "wb");
        f.rawWrite("abcdefgh\n12345678\n");
        f.close();
        // files
        PostFile[] files = [
            {fileName: tmpfname, fieldName:"abc", contentType:"application/octet-stream"},
            {fileName: tmpfname}
        ];
        rs = rq.post(httpbinUrl ~ "post", files);
        assert(rs.code==200);
    }
    info("Check POST chunked from file.byChunk");
    {
        import std.file;
        import std.path;
        auto tmpd = tempDir();
        auto tmpfname = tmpd ~ dirSeparator ~ "request_test.txt";
        auto f = File(tmpfname, "wb");
        f.rawWrite("abcdefgh\n12345678\n");
        f.close();
        f = File(tmpfname, "rb");
        rs = rq.post(httpbinUrl ~ "post", f.byChunk(3), "application/octet-stream");
        if (httpbinUrl != "http://httpbin.org/") {
            assert(rs.code==200);
            auto data = fromJsonArrayToStr(parseJSON(cast(string)rs.responseBody).object["data"]);
            assert(data=="abcdefgh\n12345678\n");
        }
        f.close();
    }
    info("Check POST chunked from lineSplitter");
    {
        auto s = lineSplitter("one,\ntwo,\nthree.");
        rs = rq.exec!"POST"(httpbinUrl ~ "post", s, "application/octet-stream");
        if (httpbinUrl != "http://httpbin.org/") {
            assert(rs.code==200);
            auto data = fromJsonArrayToStr(parseJSON(cast(string)rs.responseBody).object["data"]);
            assert(data=="one,two,three.");
        }
    }
    info("Check POST chunked from array");
    {
        auto s = ["one,", "two,", "three."];
        rs = rq.post(httpbinUrl ~ "post", s, "application/octet-stream");
        if (httpbinUrl != "http://httpbin.org/") {
            assert(rs.code==200);
            auto data = fromJsonArrayToStr(parseJSON(cast(string)rs.responseBody).object["data"]);
            assert(data=="one,two,three.");
        }
    }
    info("Check POST chunked using std.range.chunks()");
    {
        auto s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        rs = rq.post(httpbinUrl ~ "post", s.representation.chunks(10), "application/octet-stream");
        if (httpbinUrl != "http://httpbin.org/") {
            assert(rs.code==200);
            auto data = fromJsonArrayToStr(parseJSON(cast(string)rs.responseBody.data).object["data"]);
            assert(data==s);
        }
    }
    info("Check POST from QueryParams");
    {
        rs = rq.post(httpbinUrl ~ "post", queryParams("name[]", "first", "name[]", 2));
        assert(rs.code==200);
        auto data = parseJSON(cast(string)rs.responseBody).object["form"].object;
        string[] a;
        try {
            a = to!(string[])(data["name[]"].str);
        }
        catch (JSONException e) {
            a = data["name[]"].array.map!"a.str".array;
        }
        assert(equal(["first", "2"], a));
    }
    info("Check POST from AA");
    {
        rs = rq.post(httpbinUrl ~ "post", ["a":"b ", "c":"d"]);
        assert(rs.code==200);
        auto form = parseJSON(cast(string)rs.responseBody.data).object["form"].object;
        assert(form["a"].str == "b ");
        assert(form["c"].str == "d");
    }
    info("Check POST json");
    {
        rs = rq.post(httpbinUrl ~ "post?b=x", `{"a":"a b", "c":[1,2,3]}`, "application/json");
        assert(rs.code==200);
        auto json = parseJSON(cast(string)rs.responseBody).object["args"].object;
        assert(json["b"].str == "x");
        json = parseJSON(cast(string)rs.responseBody).object["json"].object;
        assert(json["a"].str == "a b");
        assert(json["c"].array.map!(a=>a.integer).array == [1,2,3]);
    }
    info("Check HEAD");
    rs = rq.exec!"HEAD"(httpbinUrl);
    assert(rs.code==200);
    info("Check DELETE");
    rs = rq.exec!"DELETE"(httpbinUrl ~ "delete");
    assert(rs.code==200);
    info("Check PUT");
    rs = rq.exec!"PUT"(httpbinUrl ~ "put",  `{"a":"b", "c":[1,2,3]}`, "application/json");
    assert(rs.code==200);
    assert(parseJSON(cast(string)rs.responseBody).object["json"].object["a"].str=="b");
    info("Check PATCH");
    rs = rq.exec!"PATCH"(httpbinUrl ~ "patch", "привiт, свiт!", "application/octet-stream");
    assert(rs.code==200);
    info("Check compressed content");
    rs = rq.get(httpbinUrl ~ "gzip");
    assert(rs.code==200);
    bool gzipped = parseJSON(cast(string)rs.responseBody).object["gzipped"].type == JSON_TYPE.TRUE;
    assert(gzipped);
    info("gzip - ok");
    rs = rq.get(httpbinUrl ~ "deflate");
    assert(rs.code==200);
    bool deflated = parseJSON(cast(string)rs.responseBody).object["deflated"].type == JSON_TYPE.TRUE;
    assert(deflated);
    info("deflate - ok");

    info("Check redirects");
    rs = rq.get(httpbinUrl ~ "relative-redirect/2");
    assert(rs.history.length == 2);
    assert(rs.code==200);
    rs = rq.get(httpbinUrl ~ "absolute-redirect/2");
    assert(rs.history.length == 2);
    assert(rs.code==200);

    rq.maxRedirects = 2;
    assertThrown!MaxRedirectsException(rq.get(httpbinUrl ~ "absolute-redirect/3"));

    info("Check cookie");
    {
        rs = rq.get(httpbinUrl ~ "cookies/set?A=abcd&b=cdef");
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
    info("Check chunked content");
    rs = rq.get(httpbinUrl ~ "range/1024");
    assert(rs.code==200);
    assert(rs.responseBody.length==1024);

    info("Check basic auth");
    rq.authenticator = new BasicAuthentication("user", "passwd");
    rs = rq.get(httpbinUrl ~ "basic-auth/user/passwd");
    assert(rs.code==200);

    info("Check limits");
    rq = HTTPRequest();
    rq.maxContentLength = 1;
    assertThrown!RequestException(rq.get(httpbinUrl));
    rq = HTTPRequest();
    rq.maxHeadersLength = 1;
    assertThrown!RequestException(rq.get(httpbinUrl));
    rq = HTTPRequest();
    info("Check POST multiPartForm");
    {
        /// This is example on usage files with MultipartForm data.
        /// For this example we have to create files which will be sent.
        import std.file;
        import std.path;
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
        MultipartForm mForm = MultipartForm().
            add(formData("Field1", cast(ubyte[])"form field from memory")).
                add(formData("Field2", cast(ubyte[])"file field from memory", ["filename":"data2"])).
                add(formData("File1", f1, ["filename":"file1", "Content-Type": "application/octet-stream"])).
                add(formData("File2", f2, ["filename":"file2", "Content-Type": "application/octet-stream"]));
        /// everything ready, send request
        rs = rq.post(httpbinUrl ~ "post", mForm);
    }
    info("Check exception handling, error messages and timeous are OK");
    rq.timeout = 1.seconds;
    assertThrown!TimeoutException(rq.get(httpbinUrl ~ "delay/3"));
//    assertThrown!ConnectError(rq.get("http://0.0.0.0:65000/"));
//    assertThrown!ConnectError(rq.get("http://1.1.1.1/"));
//    assertThrown!ConnectError(rq.get("http://gkhgkhgkjhgjhgfjhgfjhgf/"));
}
