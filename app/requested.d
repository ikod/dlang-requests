import std.stdio;
import std.format;
import std.algorithm;
import std.exception;
import std.range;
import std.getopt;
import std.experimental.logger;

import requests;

File openOutput(string output) {
    if ( output == "-" ) {
        return stdout;
    }
    auto f = File(output, "wb");
    return f;
}

int main(string[] args) {
    int         verbosity = 0;
    string      method = "GET";
    string      output = "-";
    string      loglevel = "error";
    string      proxy;

    auto    argsParsed = getopt(args,
        "verbosity|v",   "verbosity level (1,2,3)",           &verbosity,
        "method|X",      "http method (like POST,PUT,...)",   &method,
        "output|O",      "output ('-' means stdout)",         &output,
        "loglevel|l",    "loglevel (info, debug,...)",        &loglevel,
        "proxy|r",       "proxy url",                         &proxy
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
    globalLogLevel(lol);

    string url = args[1];

    Request rq = Request();
    rq.verbosity = verbosity;
    rq.useStreaming = true;

    rq.proxy = proxy;

    auto o = openOutput(output);
    scope(exit) {
        o.flush();
        o.close();
    }

    auto r = rq.execute(method, url);

    auto stream = r.receiveAsRange();
    while (!stream.empty) {
        auto b = stream.front();
//        if ( rq.contentLength ) {
//            writef("%.2f\r".format(1e2*rq.contentReceived/rq.contentLength));
//            stdout.flush();
//        }
        o.rawWrite(b);
        stream.popFront();
    }

    return 0;
}
