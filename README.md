# dlang-requests

[![Build Status](https://travis-ci.org/ikod/dlang-requests.svg?branch=master)](https://travis-ci.org/ikod/dlang-requests)

HTTP requests library with goals:

* small memory footprint
* performance
* simple, high level API

API docs: [Wiki](https://github.com/ikod/dlang-requests/wiki)

###Library configurations###

This library can either use the standard std.socket library or [vibe.d](http://vibed.org) for network IO. By default this library uses the standard std.socket configuration called *std*. To use vibe.d use the *vibed* configuration (see code example below):

```json
"dependencies": {
    "requests": "~>0.1.9"
},
"subConfigurations": {
    "requests": "vibed"
}
```

###Make a simple Request###

Making http/https/ftp request with dlang-requests is very simple. First of all install and import *requests* module:
```d
import requests;
```
Now, if all we need is content of some webpage, then we can call getContent to receive it:
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
###Request with Parameters ###

Requests propose simple way to make request with parameters. For example you have to simulate a search query for person: **name** - person name, **age** - person age, and so on... You can pass all parameters to get using *queryParams()* helper:
```d
auto content = getContent("http://httpbin.org/get", queryParams("name", "any name", "age", 42));
```
If you check httpbin response, you will see that server recognized all parameters:
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

###Posting data to server###
The easy way to post with Requests is *postContent*. There are several way to post data to server:

 1. Post to web-form using "form-urlencode" - for posting short data.
 2. Post to web-form using multipart - for large data and file uploads.
 3.  Post data to server without forms.

#### Form-urlencode ####
Call postContent in the same way as getContent with parameters:
```d
    import std.stdio;
    import requests;
    
    pragma(lib, "ssl");
    pragma(lib, "crypto");
    
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
    
    pragma(lib, "ssl");
    pragma(lib, "crypto");
    
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

When you need access to response code, or configure request details, you have to use *Request* and *Response* structures:

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
Second rq.get() will reuse previous connection to server. Request() will authomatically reopen connection when host, protocol or port changes(so it is safe to send different requests through single instance of Request). It also recover when server prematurely close keepalive connection. You can turn keepAlive off when needed:
```d
rq.keepAlive = false;
```


For anything other than default, you can configure *Request* structure for keep-alive, redirects, headers, o
r for different io-buffer and maximum sizes of response headers and body.

For example to authorize with Basic authorization use next code:
```d
    rq = Request();
    rq.authenticator = new BasicAuthentication("user", "passwd");
    rs = rq.get("http://httpbin.org/basic-auth/user/passwd");
```

Here is short descrition of some Request options, you can set:

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

contentLength and contentReceived can be used to monitor streaming response:

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

Also you can safely use *requests* with vibe.d. When *requests* compiled with support for vibe.d sockets, each call to *requests* API can block only current fiber, not thread:
```
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
