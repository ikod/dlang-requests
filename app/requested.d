import std.stdio;
import std.string;
import std.format;
import std.algorithm;
import std.exception;
import std.range;
import std.getopt;
import std.uni;
import std.experimental.logger;

import requests;

int main(string[] args) {
    int         verbosity = 0;
    string      method = "GET";
    string      output = "-";
    string      loglevel = "error";
    string      proxy;
    bool        quiet;
    string      data;
    string[]    headers;

    auto    argsParsed = getopt(args,
        "verbosity|v",   "verbosity level (1,2,3)",           &verbosity,
        "method|X",      "http method (like POST,PUT,...)",   &method,
        "header|H",      "add header",                        &headers,
        "output|O",      "output ('-' means stdout)",         &output,
        "loglevel|l",    "loglevel (info, trace,...)",        &loglevel,
        "proxy|p",       "proxy url",                         &proxy,
        "quiet|q",       "quiet run",                         &quiet,
        "data|d",        "data to send (for POST, PUT)",      &data
        );

    if ( argsParsed.helpWanted ) {
        defaultGetoptPrinter("Help:", argsParsed.options);
        return(0);
    }

    if ( args.length < 2 ) {
        stderr.writeln("No url?");
        return(1);
    }

    auto lol = [
            "error": LogLevel.error,
            "info": LogLevel.info,
            "trace": LogLevel.trace
        ].get(loglevel, LogLevel.error);

    string url = args[1];
    Request  rq = Request();
    Response r;

    rq.useStreaming = true;
    rq.proxy = proxy;

    if ( !quiet ) {
        globalLogLevel(lol);
        rq.verbosity = verbosity;
    } else {
        globalLogLevel(LogLevel.error);
    }

    auto o = openOutput(output);
    scope(exit) {
        o.flush();
        o.close();
    }

    foreach(header; headers) {
        auto h = header.split(':');
        auto hv = [h[0]:h[1].strip()];
        rq.addHeaders(hv);
    }

    method = method.toUpper();

    if ( data ) {
        if ( method == "GET") {
            throw new Exception("You must use -X switch with required HTTP method when you want to send data to server");
        }
        if (data[0] != '@' ) {
        // 'data' contains data to send
            r = rq.execute(method, url, data);
        } else {
            auto f = File(data[1..$], "rb");
            r = rq.execute(method, url, f.byChunk(16*1024));
        }
    } else {
        r = rq.execute(method, url);
    }
    auto stream = r.receiveAsRange();
    while (!stream.empty) {
        auto b = stream.front();
        show_progress(quiet, rq);
        o.rawWrite(b);
        stream.popFront();
    }

    return 0;
}

File openOutput(string output) {
    if ( output == "-" ) {
        return stdout;
    }
    auto f = File(output, "wb");
    return f;
}

void show_progress(bool quiet, in ref Request r) {

    if ( quiet ) return;

    if ( r.contentLength >= 0) {
        writef(" %10d bytes from %10d (%.2f%%)\r", r.contentReceived, r.contentLength, (1e2*r.contentReceived)/r.contentLength);
    } else {
        writef("%d from %d\r", r.contentReceived, r.contentLength);
    }
    stdout.flush();
}
