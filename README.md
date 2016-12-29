# dlang-requests

[![Build Status](https://travis-ci.org/ikod/dlang-requests.svg?branch=master)](https://travis-ci.org/ikod/dlang-requests)

HTTP requests library with goals:

* small memory footprint
* performance
* simple, high level API

API docs: [Wiki](https://github.com/ikod/dlang-requests/wiki)

### Library configurations ###

This library can either use the standard std.socket library or [vibe.d](http://vibed.org) for network IO. By default this library uses the standard std.socket configuration called *std*. To build vibe.d variant use the *vibed* configuration (see code example below):

```json
"dependencies": {
    "requests": "~>0.3.2"
},
"subConfigurations": {
    "requests": "vibed"
}
```

### Make a simple Request ###

Making http/https/ftp request with dlang-requests is simple. First of all install and import *requests* module:
```d
import requests;
```
If you need just content of some webpage, then you can use getContent:
```d
auto content = getContent("http://httpbin.org/");
```
*getContent* fetch complete document to buffer and return this buffer to the caller. *content* can be converted to string, or can be used as range. For example, if you need to count lines in *content*, you can directly apply *splitter* and *count*:
```d
writeln(content.splitter('\n').count);
```
or count non-empty lines:
```d
writeln(content.splitter('\n').filter!"a!=``".count);
```
 Actually buffer is *ForwardRange* with *length* and *random access*, so you can apply many algorithms directly to it. Or you can extract data in form of ubyte[], using method data:
```d
ubyte[] data = content.data;
```
### Request with Parameters ###

Requests propose simple way to make request with parameters. For example you have to simulate a search query for person: **name** - person name, **age** - person age, and so on... You can pass all parameters to get using *queryParams()* helper:
```d
auto content = getContent("http://httpbin.org/get", queryParams("name", "any name", "age", 42));
```
If you check httpbin response, you will see how server recognized all parameters:
```d
    {
      "args": {
        "age": "42",
        "name": "any name"
      },
      "headers": {
        "Accept-Encoding": "gzip, deflate",
        "Host": "httpbin.org",
        "User-Agent": "dlang-requests"
      },
      "origin": "xxx.xxx.xxx.xxx",
      "url": "http://httpbin.org/get?name=any name&age=42"
    }
```
Or, you can pass dictionary:
```d
auto content = getContent("http://httpbin.org/get", ["name": "any name", "age": "42"]);
```
Which give you the same response.

### If getContent fails###

 *getContent()* (and any other API call) can throw exceptions:

 * *ConnectError* when we can't connect to document origin for some reason (can't resolve name, connection refused,...)   
 * *TimeoutException* when any single operation *connect, receive, send* timed out.  
 * *ErrnoException* when we geceive ErrnoException from
   any underlying call.
 * *RequestException* in case in some other
   cases.

### Posting data to server ###
The easy way to post with Requests is *postContent*. There are several way to post data to server:

 1. Post to web-form using "form-urlencode" - for posting short data.
 2. Post to web-form using multipart - for large data and file uploads.
 3.  Post data to server without forms.

#### Form-urlencode ####
Call postContent in the same way as getContent with parameters:
```d
import std.stdio;
import requests;

void main() {
    auto content = postContent("http://httpbin.org/post", queryParams("name", "any name", "age", 42));
    writeln(content);
}
```
Output:
```
    {
      "args": {},
      "data": "",
      "files": {},
      "form": {
        "age": "42",
        "name": "any name"
      },
      "headers": {
        "Accept-Encoding": "gzip, deflate",
        "Content-Length": "22",
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "httpbin.org",
        "User-Agent": "dlang-requests"
      },
      "json": null,
      "origin": "xxx.xxx.xxx.xxx",
      "url": "http://httpbin.org/post"
    }
```
#### Multipart form ####
Posting multipart forms required MultipartForm structure to be prepared:
```d
import std.stdio;
import std.conv;
import std.string;
import requests;

void main() {
    MultipartForm form;
    form.add(formData("name", "any name"));
    form.add(formData("age", to!string(42)));
    form.add(formData("raw data", "some bytes".dup.representation));
    auto content = postContent("http://httpbin.org/post", form);
    writeln("Output:");
    writeln(content);
}
Output:
{
  "args": {},
  "data": "",
  "files": {},
  "form": {
    "age": "42",
    "name": "any name",
    "raw data": "some bytes"
  },
  "headers": {
    "Accept-Encoding": "gzip, deflate",
    "Content-Length": "332",
    "Content-Type": "multipart/form-data; boundary=e3beab0d-d240-4ec1-91bb-d47b08af5999",
    "Host": "httpbin.org",
    "User-Agent": "dlang-requests"
  },
  "json": null,
  "origin": "xxx.xxx.xxx.xxx",
  "url": "http://httpbin.org/post"
}
```
Here is example on posting file:
```d
import std.stdio;
import std.conv;
import std.string;
import requests;

void main() {
    MultipartForm form;
    form.add(formData("file", File("test.txt", "rb"), ["filename":"test.txt", "Content-Type": "text/plain"]));
    form.add(formData("age", "42"));
    auto content = postContent("http://httpbin.org/post", form);

    writeln("Output:");
    writeln(content);
}

Output:
{
  "args": {},
  "data": "",
  "files": {
    "file": "this is test file\n"
  },
  "form": {
    "age": "42"
  },
  "headers": {
    "Accept-Encoding": "gzip, deflate",
    "Content-Length": "282",
    "Content-Type": "multipart/form-data; boundary=3fd7317f-7082-4d63-82e2-16cfeaa416b4",
    "Host": "httpbin.org",
    "User-Agent": "dlang-requests"
  },
  "json": null,
  "origin": "xxx.xxx.xxx.xxx",
  "url": "http://httpbin.org/post"
}
```
#### Posting raw data without forms ####
*postContent()* can post from InputRanges. For example to post file content:
```d
import std.stdio;
import requests;

pragma(lib, "ssl");
pragma(lib, "crypto");

void main() {
    auto f = File("test.txt", "rb");
    auto content = postContent("http://httpbin.org/post", f.byChunk(5), "application/binary");
    writeln("Output:");
    writeln(content);
}

Output:
{
  "args": {},
  "data": "this is test file\n",
  "files": {},
  "form": {},
  "headers": {
    "Accept-Encoding": "gzip, deflate",
    "Content-Length": "18",
    "Content-Type": "application/binary",
    "Host": "httpbin.org",
    "User-Agent": "dlang-requests"
  },
  "json": null,
  "origin": "xxx.xxx.xxx.xxx",
  "url": "http://httpbin.org/post"
}
```
Or if your keep your data in memory, then just use something like this:
```d
auto content = postContent("http://httpbin.org/post", "ABCDEFGH", "application/binary");
```
That is all details about simple API with default request parameters. Next section will describe a lower level interface through *Request* structure.

### Request() structure ###

When you need to configure request details (like timeouts and other limits, keepalive, ssl properties), or to response details (code, headers) you have to use *Request* and *Response* structures:

```d
Request rq = Request();
Response rs = rq.get("https://httpbin.org/");
assert(rs.code==200);
```

By default we use KeepAlive requests, so you can reuse connection:
```d
import std.stdio;
import requests;

void main()
{
    auto rq = Request();
    rq.verbosity = 2;
    auto rs = rq.get("http://httpbin.org/image/jpeg");
    writeln(rs.responseBody.length);
    rs = rq.get("http://httpbin.org/image/png");
    writeln(rs.responseBody.length);
}
```
In the latter case rq.get() will reuse previous connection to server. Request() will automatically reopen connection when host, protocol or port changes(so it is safe to send different requests through single instance of Request). It also recover when server prematurely close keepalive connection. You can turn keepAlive off when needed:
```d
rq.keepAlive = false;
```

For anything other than default, you can configure *Request* structure for keep-alive, redirects handling, add/remove headers, set io-buffer size and maximum size of response headers and body.

For example to authorize with Basic authorization use next code (works both for http and ftp url's):
```d
rq = Request();
rq.authenticator = new BasicAuthentication("user", "passwd");
rs = rq.get("http://httpbin.org/basic-auth/user/passwd");
```

Here is short description of some Request options, you can set:

| name                | type           | meaning                                | default    |
|---------------------|----------------|----------------------------------------|------------|
| keepAlive           | bool           | request keepalive connection           | false      |
| maxRedirects *)     | uint           | maximum redirect depth                 | 10         |
| maxHeadersLength *) | size_t         | max.acceptable response headers length | 32KB       |
| maxContentLength *) | size_t         | max.acceptable content length          | 5MB        |
| timeout *)          | Duration       | timeout on connect or data transfer    | 30.seconds |
| bufferSize          | size_t         | socket io buffer size                  | 16KB       |
| verbosity           | uint           | verbosity level (0, 1, 2 or 3)         | 0          |
| proxy               | string         | url of the http proxy                  | null       |
| headers             | string[string] | additional headers                     | null       |
| useStreaming        | bool           | receive data as lazy InputRange        | false      |
| cookie              | Cookie[]       | cookies you will send to server        | null       |
| authenticator       | Auth           | authenticatior                         | null       |

*) Throw exception when limit reached.


Request() properties you can read:

| name             | type           | meaning                                             |
|------------------|----------------|-----------------------------------------------------|
| cookie           | Cookie[]       | cookie, server sent to us                           |
| contentLength    | long           | current document content Length or -1 if unknown    |
| contentReceived  | long           | content recived                                     |

#### Streaming server response ####
With *useStreaming* you can receive response body as input range.
contentLength and contentReceived can be used to monitor progress:

```d
import std.stdio;
import requests;

void main()
{
    auto rq = Request();
    rq.useStreaming = true;
    rq.verbosity = 2;
    auto rs = rq.get("http://httpbin.org/image/jpeg");
    auto stream = rs.receiveAsRange();
    while(!stream.empty) {
        writefln("Received %d bytes, total received %d from document legth %d", stream.front.length, rq.contentReceived, rq.contentLength);
        stream.popFront;
    }
}
```
Produce console output:
```
> GET /image/jpeg HTTP/1.1
> Connection: Keep-Alive
> User-Agent: dlang-requests
> Accept-Encoding: gzip, deflate
> Host: httpbin.org
>
< HTTP/1.1 200 OK
< server: nginx
< date: Thu, 09 Jun 2016 16:25:57 GMT
< content-type: image/jpeg
< content-length: 35588
< connection: keep-alive
< access-control-allow-origin: *
< access-control-allow-credentials: true
< 1232 bytes of body received
< 1448 bytes of body received
Received 2680 bytes, total received 2680 from document legth 35588
Received 2896 bytes, total received 5576 from document legth 35588
Received 2896 bytes, total received 8472 from document legth 35588
Received 2896 bytes, total received 11368 from document legth 35588
Received 1448 bytes, total received 12816 from document legth 35588
Received 1448 bytes, total received 14264 from document legth 35588
Received 1448 bytes, total received 15712 from document legth 35588
Received 2896 bytes, total received 18608 from document legth 35588
Received 2896 bytes, total received 21504 from document legth 35588
Received 2896 bytes, total received 24400 from document legth 35588
Received 1448 bytes, total received 25848 from document legth 35588
Received 2896 bytes, total received 28744 from document legth 35588
Received 2896 bytes, total received 31640 from document legth 35588
Received 2896 bytes, total received 34536 from document legth 35588
Received 1052 bytes, total received 35588 from document legth 35588
```
With verbosity>=3 you will receive also dump of each data portion received from sockets:
```
00000  48 54 54 50 2F 31 2E 31  20 32 30 30 20 4F 4B 0D  |HTTP/1.1 200 OK.|
00010  0A 53 65 72 76 65 72 3A  20 6E 67 69 6E 78 0D 0A  |.Server: nginx..|
00020  44 61 74 65 3A 20 53 75  6E 2C 20 32 36 20 4A 75  |Date: Sun, 26 Ju|
00030  6E 20 32 30 31 36 20 31  36 3A 31 36 3A 30 30 20  |n 2016 16:16:00 |
00040  47 4D 54 0D 0A 43 6F 6E  74 65 6E 74 2D 54 79 70  |GMT..Content-Typ|
00050  65 3A 20 61 70 70 6C 69  63 61 74 69 6F 6E 2F 6A  |e: application/j|
00060  73 6F 6E 0D 0A 54 72 61  6E 73 66 65 72 2D 45 6E  |son..Transfer-En|
00070  63 6F 64 69 6E 67 3A 20  63 68 75 6E 6B 65 64 0D  |coding: chunked.|
00080  0A 43 6F 6E 6E 65 63 74  69 6F 6E 3A 20 6B 65 65  |.Connection: kee|
...

```
Just for fun: with streaming you can forward content between servers in just two code lines. postContent will authomatically receive next data portion from source and send it to destination:
```
import requests;

void main()
{
    auto rq = Request();
    rq.useStreaming = true;
    auto stream = rq.get("https://api.github.com/search/repositories?order=desc&sort=updated&q=language:D").receiveAsRange();
    postContent("http://httpbin.org/post", stream);
}
```

You can use *requests* in parallel tasks (but you can't share single *Request* structure between threads):
```
import std.stdio;
import std.parallelism;
import std.algorithm;
import std.string;
import core.atomic;

immutable auto urls = [
    "http://httpbin.org/stream/10",
    "https://httpbin.org/stream/20",
    "http://httpbin.org/stream/30",
    "https://httpbin.org/stream/40",
    "http://httpbin.org/stream/50",
    "https://httpbin.org/stream/60",
    "http://httpbin.org/stream/70",
];

void main() {
    defaultPoolThreads(5);

    shared short lines;

    foreach(url; parallel(urls)) {
        atomicOp!"+="(lines, getContent(url).splitter("\n").count);
    }
    assert(lines == 287);
}
```
#### vibe.d ####
You can safely use *requests* with vibe.d. When *requests* compiled with support for vibe.d sockets (--config=vibed), each call to *requests* API can block only current fiber, not thread:
```d
import requests, vibe.d;

shared static this()
{
    void taskMain()
    {
        logInfo("Task created");
        auto r1 = getContent("http://httpbin.org/delay/3");
        logInfo("Delay request finished");
        auto r2 = getContent("http://google.com");
        logInfo("Google request finished");
    }

    setLogFormat(FileLogger.Format.threadTime, FileLogger.Format.threadTime);
    for(size_t i = 0; i < 3; i++)
        runTask(&taskMain);
}

output:

[F7EC2FAB:F7ECD7AB 2016.07.05 16:55:54.115 INF] Task created
[F7EC2FAB:F7ECD3AB 2016.07.05 16:55:54.116 INF] Task created
[F7EC2FAB:F7ED6FAB 2016.07.05 16:55:54.116 INF] Task created
[F7EC2FAB:F7ECD7AB 2016.07.05 16:55:57.451 INF] Delay request finished
[F7EC2FAB:F7ECD3AB 2016.07.05 16:55:57.464 INF] Delay request finished
[F7EC2FAB:F7ED6FAB 2016.07.05 16:55:57.474 INF] Delay request finished
[F7EC2FAB:F7ECD7AB 2016.07.05 16:55:57.827 INF] Google request finished
[F7EC2FAB:F7ECD3AB 2016.07.05 16:55:57.836 INF] Google request finished
[F7EC2FAB:F7ED6FAB 2016.07.05 16:55:57.856 INF] Google request finished

```
#### Adding/replacing request headers ###
Use string[string] and addHeaders method to add or replace some request headers:

 ```d
import requests;

void main() {
    auto rq = Request();
    rq.verbosity = 2;
    rq.addHeaders(["User-Agent": "test-123", "X-Header": "x-value"]);
    auto rs = rq.post("http://httpbin.org/post", `{"a":"b"}`, "application/x-www-form-urlencoded");
}
Output:
> POST /post HTTP/1.1
> Content-Length: 9
> Connection: Keep-Alive
> User-Agent: test-123
> Accept-Encoding: gzip, deflate
> Host: httpbin.org
> X-Header: x-value
> Content-Type: application/x-www-form-urlencoded
>
< HTTP/1.1 200 OK
< server: nginx
...
```
#### SSL settings ####

HTTP requests can be configured for SSL options: you can enable or disable remote server certificate verification, set key and certificate to use for authorizing to remote server:

```d
import std.stdio;
import requests;
import std.experimental.logger;

void main() {
    globalLogLevel(LogLevel.trace);
    auto rq = Request();
    rq.sslSetVerifyPeer(true); // enable peer verification
    rq.sslSetKeyFile("client01.key"); // set key file
    rq.sslSetCertFile("client01.crt"); // set cert file
    auto rs = rq.get("https://httpbin.org/");
    writeln(rs.code);
    writeln(rs.responseBody);
}
```
Please note that with vibe.d you have to add call
```d
rq.sslSetCaCert("/opt/local/etc/openssl/cert.pem");
```
with path to CA cert file(location may differ for different OS or openssl packaging).

### FTP requests ###

You can use the same structure to make ftp requests, both get and post.

HTTP specific methods do not work if request use `ftp` scheme.

Here is example:

```
import std.stdio;
import requests;

void main() {
    auto rq = Request();
    rq.verbosity = 3;
    rq.authenticator = new BasicAuthentication("login", "password");
    auto f = File("test.txt", "rb");
    auto rs = rq.post("ftp://example.com/test.txt", f.byChunk(1024));
    writeln(rs.code);
    rs = rq.get("ftp://@example.com/test.txt");
    writeln(rs.code);
}
```

Second argument for ftp posts can be anything that can be casted to ubyte[] or any InputRange with element type like ubyte[].
If path in the post request doesn't exists, then we will try to create all required directories.
As with HTTP you can call several ftp requests using same Request structure - we will reuse established connection (and authorization).

### Response() structure ###

This structure present details about received response.

Most frequently needed parts of response are:

* code - http or ftp response code as received from server.
* responseBody - contain complete document body when no streaming in use. You can't use it when in streaming mode.
* responseHeaders - response headers in form of string[string] (not available for ftp requests)
* receiveAsRange - if you set useStreaming in the Request, then receiveAsRange will provide elements(type ubyte[]) of InputRange while receiving data from the server.

### Low level details ###

At the lowest level Request() use several templated overloads of single call exec(). Using this method you can call other than GET or POST HTTP methods (Attention: you have to use HTTPRequest instead of Request, as this calls are specific to HTTP):

```d
#!/usr/bin/env rdmd -I./source librequests.a -L-lssl -L-lcrypto y.d
import std.stdio;
import requests;
import std.algorithm;

void main()
{
    auto file = File("y.d", "rb");
    auto rq = HTTPRequest();
    rq.verbosity = 2;
    auto rs = rq.exec!"PUT"("http://httpbin.org/put?exampleTitle=PUT%20content", file.byChunk(1024));
    writeln(rs.responseBody);
}

> PUT /put?exampleTitle=PUT%20content HTTP/1.1
> Transfer-Encoding: chunked
> Connection: Keep-Alive
> User-Agent: dlang-requests
> Accept-Encoding: gzip, deflate
> Host: httpbin.org
> Content-Type: text/html
>
< HTTP/1.1 200 OK
< server: nginx
< date: Sat, 11 Jun 2016 22:28:13 GMT
< content-type: application/json
< content-length: 780
< connection: keep-alive
< access-control-allow-origin: *
< access-control-allow-credentials: true
< 780 bytes of body received
{
  "args": {
    "exampleTitle": "PUT content"
  },
  "data": "#!/usr/bin/env rdmd -I./source librequests.a -L-lssl -L-lcrypto y.d\nimport std.stdio;\nimport requests;\nimport std.algorithm;\n\nvoid main()\n{\n    auto file = File(\"y.d\", \"rb\");\n    auto rq = HTTPRequest();\n    rq.verbosity = 2;\n    auto rs = rq.exec!\"PUT\"(\"http://httpbin.org/put?exampleTitle=PUT%20content\", file.byChunk(1024));\n    writeln(rs.responseBody);\n}\n\n",
  "files": {},
  "form": {},
  "headers": {
    "Accept-Encoding": "gzip, deflate",
    "Content-Length": "361",
    "Content-Type": "text/html",
    "Host": "httpbin.org",
    "User-Agent": "dlang-requests"
  },
  "json": null,
  "origin": "xxx.xxx.xxx.xxx",
  "url": "http://httpbin.org/put?exampleTitle=PUT content"
}
```

#### Requests Pool ####

When you have a large number of requests to execute, you can use request pool to speed things up.

Pool is fixed set of worker threads, receiving request *Job*'s, and returing *Result*'s.

Each Job can be configured for URL, method, data (for POST requests) and some other parameters.

Pool act as parallel map from Jobs to Results - consume InputRange of *Job*'s, and produce *InputRange* of *Result*'s as fast as it can.

It is important to note that Pool do not preserve result order. If you need somehow tie jobs and results, you can use Job's *opaque* field.

Here is sample of usage:

```d
    Job[] jobs = [
        Job("http://httpbin.org/get").addHeaders([
                            "X-Header": "X-Value",
                            "Y-Header": "Y-Value"
                        ]),
        Job("http://httpbin.org/gzip"),
        Job("http://httpbin.org/deflate"),
        Job("http://httpbin.org/absolute-redirect/3")
                .maxRedirects(2),                   // limit redirects
        Job("http://httpbin.org/range/1024"),
        Job("http://httpbin.org/post")
                .method("POST")                     // change default GET to POST
                .data("test".representation())      // attach data for POST
                .opaque("id".representation),       // opaque data - you will receive the same in Result
        Job("http://httpbin.org/delay/3")
                .timeout(1.seconds),                // set timeout to 1.seconds - this request will throw exception and fails
        Job("http://httpbin.org/stream/1024"),
        Job("ftp://speedtest.tele2.net/1KB.zip"),   // ftp requests too
    ];

    auto count = jobs.
        pool(5).
        filter!(r => r.code==200).
        count();

    assert(count == jobs.length - 2, "failed");
    // generate post data from input range
    // and process in 10 workers pool
    iota(20)
        .map!(n => Job("http://httpbin.org/post")
                        .data("%d".format(n).representation))
        .pool(10)
        .each!(r => assert(r.code==200));

```

One more example, with more features combined:

```d
import requests;
import std.stdio;
import std.string;

void main() {
    Job[] jobs_array = [
        Job("http://0.0.0.0:9998/3"),
        Job("http://httpbin.org/post").method("POST").data("test".representation()).addHeaders(["a":"b"]),
        Job("http://httpbin.org/post", Job.Method.POST, "test".representation()).opaque([1,2,3]),
        Job("http://httpbin.org/absolute-redirect/4").maxRedirects(2),
    ];
    auto p = pool(jobs_array, 10);
    while(!p.empty) {
        auto r = p.front;
        p.popFront;
        switch(r.flags) {
        case Result.OK:
            writeln(r.code);
            writeln(cast(string)r.data);
            writeln(r.opaque);
            break;
        case Result.EXCEPTION:
            writefln("Exception: %s", cast(string)r.data);
            break;
        default:
            continue;
        }
        writeln("---");
    }
}

Output:

2016-12-29T10:22:00.861:streams.d:connect:973 Failed to connect to 0.0.0.0:9998(0.0.0.0:9998): Unable to connect socket: Connection refused
2016-12-29T10:22:00.861:streams.d:connect:973 Failed to connect to 0.0.0.0:9998(0.0.0.0:9998): Unable to connect socket: Connection refused
Exception: Can't connect to 0.0.0.0:9998
---
200
{
  "args": {},
  "data": "test",
  "files": {},
  "form": {},
  "headers": {
    "A": "b",
    "Accept-Encoding": "gzip, deflate",
    "Content-Length": "4",
    "Content-Type": "application/octet-stream",
    "Host": "httpbin.org",
    "User-Agent": "dlang-requests"
  },
  "json": null,
  "origin": "xxx.xxx.xxx.xxx",
  "url": "http://httpbin.org/post"
}

[]
---
200
{
  "args": {},
  "data": "test",
  "files": {},
  "form": {},
  "headers": {
    "Accept-Encoding": "gzip, deflate",
    "Content-Length": "4",
    "Content-Type": "application/octet-stream",
    "Host": "httpbin.org",
    "User-Agent": "dlang-requests"
  },
  "json": null,
  "origin": "xxx.xxx.xxx.xxx",
  "url": "http://httpbin.org/post"
}

[1, 2, 3]
---
Exception: 2 redirects reached maxRedirects 2.
---
```

*Job* methods

| name        | parameter type           | description           |
|-------------|--------------------------|-----------------------|
| method      | *string* "GET" or "POST" | request method        |
| data        | immutable(ubyte)[]       | data for POST request |
| timeout     | Duration                 | timeout for network io|
| maxRedirects| uint                     | max N of redirects    |
| opaque      | immutable(ubyte)[]       | opaque data           |
| addHeaders  | string[string]           | headers to add to rq  |

*Result* fields

| name   | type             | description          |
|--------|------------------|----------------------|
| flags  | uint             | flags  (OK,EXCEPTION)|
| code   |ushort            | response code        |
| data   |immutable(ubyte)[]| response body        |
| opaque |immutable(ubyte)[]| opaque data from job |

### Pool limitations ###

1. currently it doesn't work under vibe.d - use vibe.d parallelisation
1. it limits you in tuning request (e.g. you can add authorization only through addHeaders, you can't tune SSL parameters, etc)
1. *Job* and *Result* *data* are immutable byte arrays (as we use send/receive for data exchange)
