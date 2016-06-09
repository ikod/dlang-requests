module requests.ftp;

private:
import std.ascii;
import std.algorithm;
import std.conv;
import std.datetime;
import std.format;
import std.socket;
import std.exception;
import std.string;
import std.range;
import std.experimental.logger;
import std.stdio;
import std.path;

import core.stdc.errno;

import requests.uri;
import requests.utils;
import requests.streams;
import requests.base;

public class FTPServerResponseError: Exception {
    this(string msg, string file = __FILE__, size_t line = __LINE__) @safe pure {
        super(msg, file, line);
    }
}

public class FTPResponse : Response {
}

public struct FTPRequest {
    private {
        URI           _uri;
        Duration      _timeout = 60.seconds;
        uint          _verbosity = 0;
        size_t        _bufferSize = 16*1024; // 16k
        long          _maxContentLength = 5*1024*1024*1024;
        long          _contentLength = -1;
        long          _contentReceived;
        SocketStream  _controlChannel;
        string[]      _responseHistory;
        FTPResponse   _response;
        bool          _useStreaming;
    }
    mixin(Getter_Setter!Duration("timeout"));
    mixin(Getter_Setter!uint("verbosity"));
    mixin(Getter_Setter!size_t("bufferSize"));
    mixin(Getter_Setter!long("maxContentLength"));
    mixin(Getter_Setter!bool("useStreaming"));
    mixin(Getter!long("contentLength"));
    mixin(Getter!long("contentReceived"));

    @property final string[] responseHistory() @safe @nogc nothrow {
        return _responseHistory;
    }
    this(string uri) {
        _uri = URI(uri);
    }

    this(in URI uri) {
        _uri = uri;
    }

    ~this() {
        if ( _controlChannel ) {
            _controlChannel.close();
        }
    }

    ushort sendCmdGetResponse(string cmd) {
        tracef("cmd to server: %s", cmd.strip);
        if ( _verbosity >=1 ) {
            writefln("> %s", cmd.strip);
        }
        _controlChannel.send(cmd);
        string response = serverResponse();
        _responseHistory ~= response;
        return responseToCode(response);
    }

    ushort responseToCode(string response) pure const @safe {
        return to!ushort(response[0..3]);
    }

    void handleChangeURI(in string uri) @safe {
        // if control channel exists and new URL not match old, then close
        URI newURI = URI(uri);
        if ( _controlChannel && 
            (newURI.host != _uri.host || newURI.port != _uri.port || newURI.username != _uri.username)) {
            _controlChannel.close();
            _controlChannel = null;
        }
        _uri = newURI;
    }

    string serverResponse() {
        string res, buffer;
        immutable bufferLimit = 16*1024;
        _controlChannel.so.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, _timeout);
        scope(exit) {
            _controlChannel.so.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, 0.seconds);
        }
        auto b = new ubyte[_bufferSize];
        while ( buffer.length < bufferLimit ) {
            trace("Wait on control channel");
            auto rc = _controlChannel.receive(b);
            version(Posix) {
                if ( rc < 0 && errno == EINTR ) {
                    continue;
                }
            }
            tracef("Got %d bytes from control socket", rc);
            if ( rc <= 0 ) {
                error("Failed to read response from server");
                throw new FTPServerResponseError("Failed to read server responce over control channel: rc=%d, errno: %d".format(rc, errno()));
            }
            if ( _verbosity >= 1 ) {
                (cast(string)b[0..rc]).
                    splitLines.
                    each!(l=>writefln("< %s", l));
            }
            buffer ~= b[0..rc];
            if ( buffer.endsWith('\n') ){
                auto responseLines = buffer.
                    splitLines.
                    filter!(l => l.length>3 && l[3]==' ' && l[0..3].all!isDigit);
                if ( responseLines.count > 0 ) {
                    return responseLines.front;
                }
            }
        }
        throw new FTPServerResponseError("Failed to read server responce over control channel");
        assert(0);
    }

    auto post(R, A...)(string uri, R data, A args) {
        enforce( uri || _uri.host, "FTP URL undefined");
        string response;
        ushort code;

        _response = new FTPResponse;

        if ( uri ) {
            handleChangeURI(uri);
        }

        _response.uri = _uri;
        _response.finalURI = _uri;

        if ( !_controlChannel ) {
            _controlChannel = new TCPSocketStream();
            _controlChannel.connect(_uri.host, _uri.port, _timeout);
            response = serverResponse();
            _responseHistory ~= response;
            
            code = responseToCode(response);
            tracef("Server initial response: %s", response);
            if ( code/100 > 2 ) {
                _response.code = code;
                return _response;
            }
            // Log in
            string user = _uri.username.length ? _uri.username : "anonymous";
            string pass = _uri.password.length ? _uri.password : "requests@";
            tracef("Use %s:%s%s as username:password", user, pass[0], replicate("-", pass.length-1));
            
            code = sendCmdGetResponse("USER " ~ user ~ "\r\n");
            if ( code/100 > 3 ) {
                _response.code = code;
                return _response;
            } else if ( code/100 == 3) {
                
                code = sendCmdGetResponse("PASS " ~ pass ~ "\r\n");
                if ( code/100 > 2 ) {
                    _response.code = code;
                    return _response;
                }
            }
            
        }

        code = sendCmdGetResponse("CWD " ~ dirName(_uri.path) ~ "\r\n");
        if ( code/100 > 2 ) {
            _response.code = code;
            return _response;
        }

        code = sendCmdGetResponse("PASV\r\n");
        if ( code/100 > 2 ) {
            _response.code = code;
            return _response;
        }
        // something like  "227 Entering Passive Mode (132,180,15,2,210,187)" expected
        // in last response.
        // Cut anything between ( and )
        auto v = _responseHistory[$-1].findSplitBefore(")")[0].findSplitAfter("(")[1];
        string host;
        ushort port;
        try {
            ubyte a1,a2,a3,a4,p1,p2;
            formattedRead(v, "%d,%d,%d,%d,%d,%d", &a1, &a2, &a3, &a4, &p1, &p2);
            host = format("%d.%d.%d.%d", a1, a2, a3, a4);
            port = (p1<<8) + p2;
        } catch (FormatException e) {
            error("Failed to parse ", v);
            _response.code = 500;
            return _response;
        }

        auto dataStream = new TCPSocketStream();
        scope (exit ) {
            if ( dataStream !is null ) {
                dataStream.close();
            }
        }

        dataStream.connect(host, port, _timeout);

        code = sendCmdGetResponse("TYPE I\r\n");
        if ( code/100 > 2 ) {
            _response.code = code;
            return _response;
        }

        code = sendCmdGetResponse("STOR " ~ baseName(_uri.path) ~ "\r\n");
        if ( code/100 > 1 ) {
            _response.code = code;
            return _response;
        }
        auto b = new ubyte[_bufferSize];
        for(size_t pos = 0; pos < data.length;) {
            auto chunk = data.take(_bufferSize).array;
            auto rc = dataStream.send(chunk);
            if ( rc <= 0 ) {
                trace("done");
                break;
            }
            tracef("sent %d bytes to data channel", rc);
            pos += rc;
        }
        dataStream.close();
        dataStream = null;
        response = serverResponse();
        code = responseToCode(response);
        if ( code/100 == 2 ) {
            tracef("Successfully uploaded %d bytes", _response._responseBody.length);
        }
        _response.code = code;
        return _response;
    }

    auto get(string uri = null) {
        enforce( uri || _uri.host, "FTP URL undefined");
        string response;
        ushort code;

        _response = new FTPResponse;

        if ( uri ) {
            handleChangeURI(uri);
        }

        _response.uri = _uri;
        _response.finalURI = _uri;

        if ( !_controlChannel ) {
            _controlChannel = new TCPSocketStream();
            _controlChannel.connect(_uri.host, _uri.port, _timeout);
            response = serverResponse();
            _responseHistory ~= response;
            
            code = responseToCode(response);
            tracef("Server initial response: %s", response);
            if ( code/100 > 2 ) {
                _response.code = code;
                return _response;
            }
            // Log in
            string user = _uri.username.length ? _uri.username : "anonymous";
            string pass = _uri.password.length ? _uri.password : "requests@";
            tracef("Use %s:%s%s as username:password", user, pass[0], replicate("-", pass.length-1));
            
            code = sendCmdGetResponse("USER " ~ user ~ "\r\n");
            if ( code/100 > 3 ) {
                _response.code = code;
                return _response;
            } else if ( code/100 == 3) {
                
                code = sendCmdGetResponse("PASS " ~ pass ~ "\r\n");
                if ( code/100 > 2 ) {
                    _response.code = code;
                    return _response;
                }
            }

        }

        code = sendCmdGetResponse("CWD " ~ dirName(_uri.path) ~ "\r\n");
        if ( code/100 > 2 ) {
            _response.code = code;
            return _response;
        }

        code = sendCmdGetResponse("TYPE I\r\n");
        if ( code/100 > 2 ) {
            _response.code = code;
            return _response;
        }
        
        code = sendCmdGetResponse("SIZE " ~ baseName(_uri.path) ~ "\r\n");
        if ( code/100 == 2 ) {
            // something like 
            // 213 229355520
            auto s = _responseHistory[$-1].findSplitAfter(" ");
            if ( s.length ) {
                try {
                    _contentLength = to!long(s[1]);
                } catch (ConvException) {
                    trace("Failed to convert string %s to file size".format(s[1]));
                }
            }
        }

        if ( _maxContentLength && _contentLength > _maxContentLength ) {
            throw new RequestException("maxContentLength exceeded for ftp data");
        }

        code = sendCmdGetResponse("PASV\r\n");
        if ( code/100 > 2 ) {
            _response.code = code;
            return _response;
        }
        // something like  "227 Entering Passive Mode (132,180,15,2,210,187)" expected
        // in last response.
        // Cut anything between ( and )
        auto v = _responseHistory[$-1].findSplitBefore(")")[0].findSplitAfter("(")[1];
        string host;
        ushort port;
        try {
            ubyte a1,a2,a3,a4,p1,p2;
            formattedRead(v, "%d,%d,%d,%d,%d,%d", &a1, &a2, &a3, &a4, &p1, &p2);
            host = format("%d.%d.%d.%d", a1, a2, a3, a4);
            port = (p1<<8) + p2;
        } catch (FormatException e) {
            error("Failed to parse ", v);
            _response.code = 500;
            return _response;
        }
        
        auto dataStream = new TCPSocketStream();
        scope (exit ) {
            if ( dataStream !is null && !_response._contentIterator.activated ) {
                dataStream.close();
            }
        }
        
        dataStream.connect(host, port, _timeout);
        
        code = sendCmdGetResponse("RETR " ~ baseName(_uri.path) ~ "\r\n");
        if ( code/100 > 1 ) {
            _response.code = code;
            return _response;
        }
        auto b = new ubyte[_bufferSize];
        while ( true ) {
            auto rc = dataStream.receive(b);
            if ( rc <= 0 ) {
                trace("done");
                break;
            }
            _contentReceived += rc;
            tracef("got %d bytes from data channel", rc);
            _response._responseBody.put(b[0..rc]);

            if ( _maxContentLength && _response._responseBody.length >= _maxContentLength ) {
                throw new RequestException("maxContentLength exceeded for ftp data");
            }
            if ( _useStreaming ) {
                _response.contentIterator.activated = true;
                _response.contentIterator.data = _response._responseBody;
                _response.contentIterator.b = new ubyte[_bufferSize];
                _response.contentIterator.read = delegate Buffer!ubyte () {
                    Buffer!ubyte result;
                    while(true) {
                        // check if we received everything we need
                        if ( _contentReceived >= _maxContentLength ) 
                        {
                            throw new RequestException("ContentLength > maxContentLength (%d>%d)".
                                format(_contentLength, _maxContentLength));
                        }
                        // have to continue
                        auto read = dataStream.receive(_response.contentIterator.b);
                        tracef("streaming_in received %d bytes", read);
                        if ( read < 0 ) {
                            version(Posix) {
                                if ( errno == EINTR ) {
                                    continue;
                                }
                            }
                            throw new RequestException("streaming_in error reading from socket");
                        }
                        if ( read == 0 ) {
                            tracef("streaming_in: server closed connection");
                            dataStream.close();
                            code = responseToCode(serverResponse());
                            if ( code/100 == 2 ) {
                                tracef("Successfully received %d bytes", _response._responseBody.length);
                            }
                            _response.code = code;
                            break;
                        }
                        _contentReceived += read;
                        result = Buffer!ubyte(_response.contentIterator.b[0..read].dup);
                        if ( result.length ) {
                            tracef("return %d bytes", result.length);
                            break;
                        }
                    }
                    return result;
                };
                return _response;
            }
        }
        dataStream.close();
        response = serverResponse();
        code = responseToCode(response);
        if ( code/100 == 2 ) {
            tracef("Successfully received %d bytes", _response._responseBody.length);
        }
        _response.code = code;
        return _response;
    }
}

package unittest {
    globalLogLevel(LogLevel.info );
    info("testing ftp");
    auto rq = FTPRequest();
    info("ftp post ", "ftp://speedtest.tele2.net/upload/TEST.TXT");
    auto rs = rq.post("ftp://speedtest.tele2.net/upload/TEST.TXT", "test, ignore please\n".representation);
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
    assert(rs.finalURI.path == "/pub/FreeBSD/README.TXT");
    info("testing ftp - done.");
}