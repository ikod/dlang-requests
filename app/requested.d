import std.stdio;
import std.algorithm;
import std.exception;
import std.range;
import std.getopt;

import requests;

int main(string[] args) {
    int         verbosity = 0;
    string      method = "GET";
    string      output;

    auto    argsParsed = getopt(args,
        "verbosity|v",   "verbosity level (1,2,3)",           &verbosity,
        "method|X",      "http method (like POST,PUT,...)",   &method,
        "output|O",      "output ('-' means stdout)",         &output
        );

    if ( argsParsed.helpWanted ) {
        defaultGetoptPrinter("Help:", argsParsed.options);
        return(0);
    }

    if ( args.length < 2 ) {
        stderr.writeln("No url?");
        return(1);
    }
    string url = args[1];

    Request rq = Request();
    rq.verbosity = verbosity;

    auto r = rq.execute(method, url);
    writeln(r.code);
    writeln(r.responseBody);
    return 0;
}
