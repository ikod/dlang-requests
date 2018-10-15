module requests.base;

import requests.streams;
import requests.utils;
import requests.uri;

import std.format;
import std.datetime;
import core.time;
import std.stdio;
import std.algorithm;
import std.string;
import std.exception;
import std.bitmanip;

public interface Auth {
    string[string] authHeaders(string domain);
    string         userName();
    string         password();
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

private immutable uint defaultBufferSize = 12*1024;
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

    package FormData[] _sources;
    auto add(FormData d) {
        _sources ~= d;
        return this;
    }
    auto add(string name, FiniteReadable i, string[string]parameters = null) {
        _sources ~= FormData(name, i, parameters);
        return this;
    }
    bool empty() const
    {
        return _sources.length == 0;
    }
}
///

public class RequestException: Exception {
    this(string msg, string file = __FILE__, size_t line = __LINE__, Throwable next = null) @safe pure nothrow {
        super(msg, file, line, next);
    }
}

public struct ReceiveAsRange {
    bool empty() {
        return data.length == 0;
    }
    ubyte[] front() {
        return data;
    }
    void popFront() {
        if ( read ) {
            // get new portion
            data = read();
        } else {
            // we can't read any new data
            data.length = 0;
        }
    }
    package {
        bool            activated;
        ubyte[]         data;
        ubyte[]         delegate() read;
    }
}

public class Response {
    package {
        ushort           _code;
        Buffer!ubyte     _responseBody;
        string[string]   _responseHeaders;
        /// Initial URI
        URI              _uri;
        /// Final URI. Can differ from __URI if request go through redirections.
        URI              _finalURI;
        ReceiveAsRange   _receiveAsRange;
        SysTime          _startedAt,
                         _connectedAt,
                         _requestSentAt,
                         _finishedAt;
        long             _contentReceived;
        long             _contentLength = -1;
        mixin(Setter!ushort("code"));
        mixin(Setter!URI("uri"));
        mixin(Setter!URI("finalURI"));
    }
    mixin(Getter("code"));
    mixin(Getter("contentReceived"));
    mixin(Getter("contentLength"));
    mixin(Getter("uri"));
    mixin(Getter("finalURI"));
    @property auto ref responseBody() @safe nothrow {
        return _responseBody;
    }
    @property auto ref responseHeaders() pure @safe nothrow {
        return _responseHeaders;
    }
    @property auto ref receiveAsRange() pure @safe nothrow {
        return _receiveAsRange;
    }
    override string toString() const {
        return "Response(%d, %s)".format(_code, _uri.uri());
    }
    string format(string fmt) const {
        import std.array;
        auto a = appender!string();
        auto f = FormatSpec!char(fmt);
        while (f.writeUpToNextSpec(a)) {
            switch (f.spec) {
                case 'h':
                    // Remote hostname.
                    a.put(_uri.host);
                    break;
                case 'p':
                    // Remote port.
                    a.put("%d".format(_uri.port));
                    break;
                case 'P':
                    // Path.
                    a.put(_uri.path);
                    break;
                case 'q':
                    // query parameters supplied with url.
                    a.put(_uri.query);
                    break;
                case 's':
                    a.put("Response(%d, %s)".format(_code, _uri.uri()));
                    break;
                case 'B': // received bytes
                    a.put("%d".format(_responseBody.length));
                    break;
                case 'T': // request total time, ms
                    a.put("%d".format((_finishedAt - _startedAt).total!"msecs"));
                    break;
                case 'U':
                    a.put(_uri.uri());
                    break;
                case 'S':
                    a.put("%d".format(_code));
                    break;
                default:
                    throw new FormatException("Unknown Response format specifier: %" ~ f.spec);
            }
        }
        return a.data();
    }
}

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
