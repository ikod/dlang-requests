import std.stdio;
import std.string;
import std.format;
import std.algorithm;
import std.exception;
import std.range;
import std.getopt;
import std.uni;
import std.path;
import std.file;
import std.digest.md;
import std.base64;
import std.experimental.logger;

version(Posix) {
    import core.sys.posix.signal;
    import core.stdc.stdlib;
}

import requests;

struct Control {
    File    file;
    string  temporaryNameBase;  /* without coded id                                 */
    string  temporaryName;      /* temporary file where we receive data             */
    string  finalName;          /* final dest; rename to this on success            */
    string  id;                 /* ETag or Last-Modified from old temp file         */
    string  doc_id;             /* ETag or Last-Modified from http headers          */
    ulong   restart_from;       /* restart position                                 */

    bool canResume() const {
        return ctrl.id != "" && ctrl.restart_from > 0;
    }
    void writeFromBeginning() {
        file.close();
        file = File(temporaryName, "wb");
        restart_from = 0;
    }
}

extern (C) void sigHandler(int value) {
    handleFailure();
    exit(1);
}

static Control ctrl;

void handleFailure() {
    if ( ctrl.finalName == "-" ) {
        ctrl.file.flush();
        ctrl.file.close();
        return;
    }
    ctrl.file.flush();
    ctrl.file.close();
    if ( ctrl.id != ctrl.doc_id ) {
        // we have to rename temporary file so it keep id (ETag or LastModified base64-encoded)
        rename(ctrl.temporaryName, "%s-%s".format(ctrl.temporaryNameBase, Base64.encode(ctrl.doc_id.representation)));
    }
}
void handleSuccess() {
    if ( ctrl.finalName == "-" ) {
        ctrl.file.flush();
        ctrl.file.close();
        return;
    }
    ctrl.file.flush();
    ctrl.file.close();
    // we have to rename temporary file to final name
    rename(ctrl.temporaryName, ctrl.finalName);
}

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

    method = method.toUpper();

    string url = args[1];
    Request  rq = Request();
    Response r;

    rq.useStreaming = true;
    rq.proxy = proxy;

    if ( output == "-" ) {
        quiet = true;
    }

    if ( !quiet ) {
        globalLogLevel(lol);
        rq.verbosity = verbosity;
    } else {
        globalLogLevel(LogLevel.error);
    }

    sigset(SIGINT, &sigHandler);

    ctrl = createOutputControl(url, output);

    scope(success) {
        handleSuccess();
    }
    scope(failure) {
        handleFailure();
    }

    if ( method == "GET" && ctrl.canResume() ) {
        // will resume from some position
        string[string] restartHeaders;
        restartHeaders["If-Range"] = "%s".format(ctrl.id);
        restartHeaders["Range"] = "bytes=%d-".format(ctrl.restart_from);
        rq.addHeaders(restartHeaders);
    }
    foreach(header; headers) {
        auto h = header.split(':');
        auto hv = [h[0]:h[1].strip()];
        rq.addHeaders(hv);
    }

    if ( data ) {
        if ( method == "GET") {
            throw new Exception("You must use -X switch with proper HTTP method (PUT/POST/...) when you want to send data to server");
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
    auto r_headers = r.responseHeaders;

    auto ETag = "etag" in r_headers;
    auto LastModified = "last-modified" in r_headers;

    ctrl.doc_id = ETag ? *ETag : (LastModified ? *LastModified : "");
    if ( r.code != 206 && output != "-" ) {
        ctrl.writeFromBeginning();
    }
    auto o = ctrl.file;
    auto stream = r.receiveAsRange();

    while (!stream.empty) {
        auto b = stream.front();
        o.rawWrite(b);
        stream.popFront();

        if ( !quiet ) {
            show_progress(rq, r, ctrl);
        }
    }
    return 0;
}

Control createOutputControl(string url, string output) {
    Control v;
    if ( output == "-" ) {
        v.finalName = output;
        v.file = stdout;
        return v;
    }
    auto outDirectory = dirName(output);
    auto md5 = new MD5Digest();
    auto urlHash = md5.digest(url).toHexString();
    auto tempNameBase = outDirectory ~ dirSeparator ~ "part." ~ urlHash;
    string tempBestName = getBestTmpCandidate(tempNameBase);
    v.temporaryNameBase = tempNameBase;
    v.temporaryName = tempBestName;
    v.finalName = output;
    v.file = File(tempBestName, "ab");
    v.restart_from = getSize(tempBestName);
    v.id = getEtagOrLastModified(tempBestName);
    writeln(v);
    return v;
}
/**
 ** create temporary name from url in the output directory
 **/
string tmpName(string url, string output) {
    auto outDirectory = dirName(output);
    auto md5 = new MD5Digest();
    auto urlHash = md5.digest(url).toHexString();
    auto tempNameBase = outDirectory ~ dirSeparator ~ "part." ~ urlHash;
    return tempNameBase;
}
unittest {
    assert(tmpName("http://abc.com/file.zip", "")[2..$] == "part.138DCBF6527F53E53BCCB3F38AC8D7F8");
}

/**
 ** get best candidate
 **/
string getBestTmpCandidate(string name) {
    string candidate;
    auto outDirectory = dirName(name);
    auto entries =
        dirEntries(outDirectory, SpanMode.shallow)
        .filter!(a => globMatch(a.name, name ~ "*"))
        .array
        .sort!"a.timeLastModified<b.timeLastModified";
    if ( entries.empty ) {
        candidate = name;
    } else {
        writeln("try to resume");
        candidate = entries[$-1].name;
    }
    return candidate;
}

/**
 * Extract document "id" (Etag ond/or Last-Modified) from partial name.
 * Take name in form part.hex(urlHash)-base64(id) and split on fields
 * part.32hexchars-base64string
 **/
string getEtagOrLastModified(string fn) {
    auto v = split(fn, "-");
    if (v.length == 2) {
        return assumeUTF(Base64.decode(v[1]));
    }
    return "";
}
unittest {
    assert(getEtagOrLastModified("123") == "");
    assert(getEtagOrLastModified("123-YQ==") == "a");
    assert(getEtagOrLastModified("123--b") == "");
    assert(getEtagOrLastModified("123-a-") == "");
    assert(getEtagOrLastModified("123-YWI=") == "ab");
}

void show_progress(in ref Request rq, in ref Response rs, in ref Control c) {
    auto received = rq.contentReceived;
    auto documentLength = rq.contentLength;
    if ( rs.code == 206 ) {
        received += c.restart_from;
        documentLength += c.restart_from;
    }
    if ( documentLength >= 0) {
        writef(" %10d bytes from %10d (%.2f%%)\r", received, rq.contentLength, (1e2*received)/documentLength);
    } else {
        writef("%d from %d\r", received, rq.contentLength);
    }
    stdout.flush();
}
