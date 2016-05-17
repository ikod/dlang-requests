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

import requests.uri;
import requests.utils;
import requests.streams;

public class FTPServerResponseError: Exception {
    this(string msg, string file = __FILE__, size_t line = __LINE__) @safe pure {
        super(msg, file, line);
    }
}

struct FTPResponse {
    ushort       __code;
    Buffer!ubyte __responseBody;
    mixin(getter("code"));
    @property auto responseBody() inout pure @safe {
        return __responseBody;
    }
}

struct FTPRequest {
    URI           __uri;
    Duration      __timeout = 60.seconds;
    uint          __verbosity = 0;
    size_t        __bufferSize = 16*1024; // 16k
    SocketStream  __controlChannel;
    string[]      __responseHistory;
    FTPResponse   __response;

    mixin(setter("timeout"));
    mixin(getter("timeout"));
    mixin(setter("verbosity"));
    mixin(getter("verbosity"));

    this(string uri) {
        __uri = URI(uri);
    }
    this(in URI uri) {
        __uri = uri;
    }
   ~this() {
        if ( __controlChannel ) {
            __controlChannel.close();
        }
    }
    ushort sendCmdGetResponse(string cmd) {
        tracef("cmd to server: %s", cmd.strip);
        if ( __verbosity >=1 ) {
            writefln("> %s", cmd.strip);
        }
        __controlChannel.send(cmd);
        string response = serverResponse();
        __responseHistory ~= response;
        return responseToCode(response);
    }

    ushort responseToCode(string response) pure const {
        return to!ushort(response[0..3]);
    }

    string serverResponse() {
        string res, buffer;
        immutable bufferLimit = 16*1024;
        __controlChannel.so.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, __timeout);
        scope(exit) {
            __controlChannel.so.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, 0.seconds);
        }
        auto b = new ubyte[__bufferSize];
        while ( buffer.length < bufferLimit ) {
            trace("Wait on control channel");
            auto rc = __controlChannel.receive(b);
            tracef("Got %d bytes from control socket", rc);
            if ( rc <= 0 ) {
                error("Failed to read response from server");
                throw new FTPServerResponseError("Failed to read server responce over control channel");
            }
            if ( __verbosity >= 1 ) {
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
    }

    auto post(R)(string uri = null, R data = null) {
        enforce( uri || __uri.host, "FTP URL undefined");
        string response;
        ushort code;

        __response = FTPResponse.init;

        if ( uri ) {
            // if control channel exists and new URL not match old, then close
            URI __new = URI(uri);
            if ( __controlChannel && 
                (__new.host != __uri.host || __new.port != __uri.port || __new.username != __uri.username)) {
                __controlChannel.close();
                __controlChannel = null;
            }
            __uri = __new;
        }
        if ( !__controlChannel ) {
            __controlChannel = new TCPSocketStream();
            __controlChannel.connect(__uri.host, __uri.port, __timeout);
            response = serverResponse();
            __responseHistory ~= response;
            
            code = responseToCode(response);
            tracef("Server initial response: %s", response);
            if ( code/100 > 2 ) {
                __response.__code = code;
                return __response;
            }
            // Log in
            string user = __uri.username.length ? __uri.username : "anonymous";
            string pass = __uri.password.length ? __uri.password : "requests@";
            tracef("Use %s:%s%s as username:password", user, pass[0], replicate("-", pass.length-1));
            
            code = sendCmdGetResponse("USER " ~ user ~ "\r\n");
            if ( code/100 > 3 ) {
                __response.__code = code;
                return __response;
            } else if ( code/100 == 3) {
                
                code = sendCmdGetResponse("PASS " ~ pass ~ "\r\n");
                if ( code/100 > 2 ) {
                    __response.__code = code;
                    return __response;
                }
            }
            
        }

        code = sendCmdGetResponse("CWD " ~ dirName(__uri.path) ~ "\r\n");
        if ( code/100 > 2 ) {
            __response.__code = code;
            return __response;
        }

        code = sendCmdGetResponse("PASV\r\n");
        if ( code/100 > 2 ) {
            __response.__code = code;
            return __response;
        }
        // something like  "227 Entering Passive Mode (132,180,15,2,210,187)" expected
        // in last response.
        // Cut anything between ( and )
        auto v = __responseHistory[$-1].findSplitBefore(")")[0].findSplitAfter("(")[1];
        string host;
        ushort port;
        try {
            ubyte a1,a2,a3,a4,p1,p2;
            formattedRead(v, "%d,%d,%d,%d,%d,%d", &a1, &a2, &a3, &a4, &p1, &p2);
            host = format("%d.%d.%d.%d", a1, a2, a3, a4);
            port = (p1<<8) + p2;
        } catch (FormatException e) {
            error("Failed to parse ", v);
            __response.__code = 500;
            return __response;
        }

        auto __dataStream = new TCPSocketStream();
        scope (exit ) {
            __dataStream.close();
        }

        __dataStream.connect(host, port, __timeout);

        code = sendCmdGetResponse("TYPE I\r\n");
        if ( code/100 > 2 ) {
            __response.__code = code;
            return __response;
        }

        code = sendCmdGetResponse("STOR " ~ baseName(__uri.path) ~ "\r\n");
        if ( code/100 > 1 ) {
            __response.__code = code;
            return __response;
        }
        auto b = new ubyte[__bufferSize];
        for(size_t pos = 0; pos < data.length;) {
            auto chunk = data.take(__bufferSize).array;
            auto rc = __dataStream.send(chunk);
            if ( rc <= 0 ) {
                trace("done");
                break;
            }
            tracef("sent %d bytes to data channel", rc);
            pos += rc;
        }
        __dataStream.close();
        response = serverResponse();
        code = responseToCode(response);
        if ( code/100 == 2 ) {
            tracef("Successfully uploaded %d bytes", __response.__responseBody.length);
        }
        __response.__code = code;
        return __response;
    }
    auto get(string uri = null) {
        enforce( uri || __uri.host, "FTP URL undefined");
        string response;
        ushort code;

        __response = FTPResponse.init;

        if ( uri ) {
            // if control channel exists and new URL not match old, then close
            URI __new = URI(uri);
            if ( __controlChannel && 
                (__new.host != __uri.host || __new.port != __uri.port || __new.username != __uri.username)) {
                __controlChannel.close();
                __controlChannel = null;
            }
            __uri = __new;
        }
        if ( !__controlChannel ) {
            __controlChannel = new TCPSocketStream();
            __controlChannel.connect(__uri.host, __uri.port, __timeout);
            response = serverResponse();
            __responseHistory ~= response;
            
            code = responseToCode(response);
            tracef("Server initial response: %s", response);
            if ( code/100 > 2 ) {
                __response.__code = code;
                return __response;
            }
            // Log in
            string user = __uri.username.length ? __uri.username : "anonymous";
            string pass = __uri.password.length ? __uri.password : "requests@";
            tracef("Use %s:%s%s as username:password", user, pass[0], replicate("-", pass.length-1));
            
            code = sendCmdGetResponse("USER " ~ user ~ "\r\n");
            if ( code/100 > 3 ) {
                __response.__code = code;
                return __response;
            } else if ( code/100 == 3) {
                
                code = sendCmdGetResponse("PASS " ~ pass ~ "\r\n");
                if ( code/100 > 2 ) {
                    __response.__code = code;
                    return __response;
                }
            }

        }

        code = sendCmdGetResponse("CWD " ~ dirName(__uri.path) ~ "\r\n");
        if ( code/100 > 2 ) {
            __response.__code = code;
            return __response;
        }
        
        code = sendCmdGetResponse("PASV\r\n");
        if ( code/100 > 2 ) {
            __response.__code = code;
            return __response;
        }
        // something like  "227 Entering Passive Mode (132,180,15,2,210,187)" expected
        // in last response.
        // Cut anything between ( and )
        auto v = __responseHistory[$-1].findSplitBefore(")")[0].findSplitAfter("(")[1];
        string host;
        ushort port;
        try {
            ubyte a1,a2,a3,a4,p1,p2;
            formattedRead(v, "%d,%d,%d,%d,%d,%d", &a1, &a2, &a3, &a4, &p1, &p2);
            host = format("%d.%d.%d.%d", a1, a2, a3, a4);
            port = (p1<<8) + p2;
        } catch (FormatException e) {
            error("Failed to parse ", v);
            __response.__code = 500;
            return __response;
        }
        
        auto __dataStream = new TCPSocketStream();
        scope (exit ) {
            __dataStream.close();
        }
        
        __dataStream.connect(host, port, __timeout);
        
        code = sendCmdGetResponse("TYPE I\r\n");
        if ( code/100 > 2 ) {
            __response.__code = code;
            return __response;
        }
        
        code = sendCmdGetResponse("RETR " ~ baseName(__uri.path) ~ "\r\n");
        if ( code/100 > 1 ) {
            __response.__code = code;
            return __response;
        }
        auto b = new ubyte[__bufferSize];
        while ( true ) {
            auto rc = __dataStream.receive(b);
            if ( rc <= 0 ) {
                trace("done");
                break;
            }
            tracef("got %d bytes from data channel", rc);
            __response.__responseBody.put(b[0..rc]);
        }
        __dataStream.close();
        response = serverResponse();
        code = responseToCode(response);
        if ( code/100 == 2 ) {
            tracef("Successfully received %d bytes", __response.__responseBody.length);
        }
        __response.__code = code;
        return __response;
    }
}

unittest {
    globalLogLevel(LogLevel.info );
    info("testing ftp");
    auto rq = FTPRequest();
    info("ftp post ", "ftp://speedtest.tele2.net/upload/TEST.TXT");
    auto rs = rq.post("ftp://speedtest.tele2.net/upload/TEST.TXT", "test, ignore please\n".representation);
    assert(rs.code == 226);
    info("ftp get  ", "ftp://speedtest.tele2.net/1KB.zip", " - same session.");
    rs = rq.get("ftp://speedtest.tele2.net/1KB.zip");
    assert(rs.code == 226);
    assert(rs.responseBody.length == 1024);
    info("ftp get  ", "ftp://ftp.uni-bayreuth.de/README");
    rs = rq.get("ftp://ftp.uni-bayreuth.de/README");
    assert(rs.code == 226);
    info("ftp post ", "ftp://speedtest.tele2.net/upload/TEST.TXT");
    rs = rq.post("ftp://speedtest.tele2.net/upload/TEST.TXT", "another test, ignore please\n".representation);
    assert(rs.code == 226);
    info("testing ftp - done.");
}