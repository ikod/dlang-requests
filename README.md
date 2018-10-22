# dlang-requests

[![Build Status](https://travis-ci.org/ikod/dlang-requests.svg?branch=master)](https://travis-ci.org/ikod/dlang-requests)

HTTP client library, inspired by python-requests with goals:

* small memory footprint
* performance
* simple, high level API
* native D implementation

API docs: [Wiki](https://github.com/ikod/dlang-requests/wiki)

## Table of contents

- [Library configurations (std.socket and vibe sockets)](#library-configurations)
- [Levels of API](#two-levels-of-api)
- [Quick start](#make-a-simple-request)
- [Requests with parameters](#request-with-parameters)
- [Posting data](#posting-data-to-server)
   - [Posting url-encoded](#form-urlencode)
   - [Posting multipart](#multipart-form)
   - [Posting raw data](#posting-raw-data-without-forms)
- [Properties of Request structure](#request-structure)
- [Streaming response](#streaming-server-response)
- [Modifying request(headers, etc.)](#addingreplacing-request-headers)
- [SSL](#ssl-settings)
- [FTP](#ftp-requests)
- [Request pool](#requests-pool)


### Library configurations ###

This library can either use standard `std.socket` library or [`vibe.d`](http://vibed.org) for network IO. By default this library uses the standard `std.socket` configuration called `std`. To build `vibed` variant, use the `vibed` configuration:

```json
"dependencies": {
    "requests": "~>1"
},
"subConfigurations": {
    "requests": "vibed"
}
```

### Two levels of API ###
* At the highest API level you interested only in retrieving or posting document content.
Use it when you don't need to add headers, set timeouts, or change any other defaults, 
if you don't interested in result codes or any details of request and/or
response. This level propose only two calls: `getContent` and `postContent`.
What you receive is a Buffer, which you can use as range, but you can easily 
convert it to `ubyte[]` using `.data` property.

* At the next level we have `Request` structure, which encapsulate all details and settings 
required for http(s)/ftp transfer. Operating on `Request` instance you can 
change many aspects of interaction with http/ftp server. Most important API 
calls are `Request.get()`, `Reuest.post` or `Request.exec!"method"` and so 
on (you will find examples below). You will receive `Response` with all available
details -document body, status code, headers, timings, etc.


#### Windows ssl notes ####
In case `requests` can't find opsn ssl library on Windows, here is several steps that can help:
1. From the [slproweb](https://slproweb.com/products/Win32OpenSSL.html) download [openssl](https://slproweb.com/download/Win32OpenSSL_Light-1_0_2o.exe) binaries for Windows.
1. Install it. **Important**: allow installer to install libraries in system folders.

See step-by-step instructions [here](https://github.com/ikod/dlang-requests/issues/77#issuecomment-405911012).

### Make a simple request ###

Making HTTP/HTTPS/FTP requests with `dlang-requests` is simple. First of all, install and import `requests` module:

```d
import requests;
```

If you only need content of some webpage, you can use `getContent()`:

```d
auto content = getContent("http://httpbin.org/");
```

`getContent()` will fetch complete document to buffer and return this buffer to the caller. `content` can be converted to string, or can be used as range. For example, if you need to count lines in `content`, you can directly apply `splitter()` and `count`:

```d
writeln(content.splitter('\n').count);
```

Count non-empty lines:

```d
writeln(content.splitter('\n').filter!"a!=``".count);
```

Actually, the buffer is a `ForwardRange` with `length` and random access, so you can apply many algorithms directly to it. Or you can extract data in form of `ubyte[]`, using `data` property:

```d
ubyte[] data = content.data;
```


### Request with parameters ###

`dlang-requests` proposes simple way to make a request with parameters. For example, you have to simulate a search query for person: **name** - person name, **age** - person age, and so on... You can pass all parameters to get using `queryParams()` helper:

```d
auto content = getContent("http://httpbin.org/get", queryParams("name", "any name", "age", 42));
```

If you check httpbin response, you will see that server recognized all parameters:

```json
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

Which gives you the same response.


### If `getContent()` fails###

 `getContent()` (and any other API call) can throw the following exceptions:

 * `ConnectError` when it can't connect to document origin for some reason (can't resolve name, connection refused, ...)   
 * `TimeoutException` when any single operation *(connect, receive, send)* timed out.  
 * `ErrnoException` when received `ErrnoException` from any underlying call.
 * `RequestException` in some other cases.


### Posting data to server ###

The easy way to post with `dlang-requests` is `postContent()`. There are several ways to post data to server:

 1. Post to web-form using `application/x-www-form-urlencoded` - for posting short data.
 1. Post to web-form using `multipart/form-data` - for large data and file uploads.
 1. Post data to server without forms.

#### Form-urlencode ####

Call `postContent()` in the same way as `getContent()` with parameters:

```d
import std.stdio;
import requests;

void main() {
    auto content = postContent("http://httpbin.org/post", queryParams("name", "any name", "age", 42));
    writeln(content);
}
```

Output:

```json
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

Posting multipart forms requires `MultipartForm` structure to be prepared:

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
```

Output:

```json
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

Here is an example of posting a file:

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
```

Output:

```json
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

`postContent()` can post from `InputRange`s. For example, to post file content:

```d
import std.stdio;
import requests;

void main() {
    auto f = File("test.txt", "rb");
    auto content = postContent("http://httpbin.org/post", f.byChunk(5), "application/binary");
    writeln("Output:");
    writeln(content);
}
```

Output:

```json
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

Or, if you keep your data in memory, you can use something like this:

```d
auto content = postContent("http://httpbin.org/post", "ABCDEFGH", "application/binary");
```

Those are all details about simple API with default request parameters. The next section will describe a lower-level interface through `Request` structure.


### `Request` structure ###

When you need to configure request details (like timeouts and other limits, keep-alive, ssl properties), or response details (code, headers), you have to use `Request` and `Response` structures:

```d
Request rq = Request();
Response rs = rq.get("https://httpbin.org/");
assert(rs.code==200);
```


By default Keep-Alive requests are used, so you can reuse the connection:

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

In the latter case `rq.get()` will reuse previous connection to server.
`Request` will automatically reopen connection when host, protocol or port change (so it is safe
to send different requests through single instance of `Request`).
It also recovers when server prematurely closes keep-alive connection.
You can turn `keepAlive` off when needed:

```d
rq.keepAlive = false;
```

For anything other than default, you can configure `Request` structure for keep-alive, redirects handling, to add/remove headers, set IO buffer size and maximum size of response headers and body.

For example, to authorize with basic authentication, use the following code (works both for HTTP and FTP URLs):

```d
rq = Request();
rq.authenticator = new BasicAuthentication("user", "passwd");
rs = rq.get("http://httpbin.org/basic-auth/user/passwd");
```

Here is a short description of some `Request` options you can set:

| name                | type             | meaning                                 | default    |
|---------------------|------------------|-----------------------------------------|------------|
| keepAlive           | `bool`           | request keepalive connection            | true       |
| maxRedirects *)     | `uint`           | maximum redirect depth (0 to disable)   | 10         |
| maxHeadersLength *) | `size_t`         | max. acceptable response headers length | 32KB       |
| maxContentLength *) | `size_t`         | max. acceptable content length          | 5MB        |
| timeout *)          | `Duration`       | timeout on connect or data transfer     | 30.seconds |
| bufferSize          | `size_t`         | socket io buffer size                   | 16KB       |
| verbosity           | `uint`           | verbosity level (0, 1, 2 or 3)          | 0          |
| proxy               | `string`         | url of the HTTP proxy                   | null       |
| addHeaders          | `string[string]` | additional headers                      | null       |
| useStreaming        | `bool`           | receive data as lazy `InputRange`       | false      |
| cookie              | `Cookie[]`       | cookies you will send to server         | null       |
| authenticator       | `Auth`           | authenticatior                          | null       |
| bind                | `string`         | use local address whan connect          | null       |
| socketFactory**)    | (see below)      | user-provided connection factory        | null       |

*) Throws exception when limit is reached.

**) If provided - each time `Request` need new connection it will call factory to create instance of NetworkStream.
This way you can implement (outside of this library) lot of useful things: various proxies, unix-socket connections, etc.

`Request` properties that are read-only:

| name             | type             | meaning                                             |
|------------------|------------------|-----------------------------------------------------|
| cookie           | `Cookie[]`       | cookie the server sent to us                        |
| contentLength    | `long`           | current document's content length or -1 if unknown  |
| contentReceived  | `long`           | content received                                    |


##### Redirect and connection optimisations #####

`Request` keep results of Permanent redirections in small cache. It also keep map
`(schema,host,port) -> connection` of opened connections, for subsequent usage.

### Streaming server response ###
With `useStreaming`, you can receive response body as input range.
`contentLength` and `contentReceived` can be used to monitor progress:

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
        writefln("Received %d bytes, total received %d from document legth %d", stream.front.length, rs.contentReceived, rs.contentLength);
        stream.popFront;
    }
}
```

Output:

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

With `verbosity >= 3`, you will also receive a dump of each data portion received from sockets:

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

Just for fun: with streaming you can forward content between servers in just two code lines. `postContent` will automatically receive next data portion from source and send it to destination:

```d
import requests;

void main()
{
    auto rq = Request();
    rq.useStreaming = true;
    auto stream = rq.get("https://api.github.com/search/repositories?order=desc&sort=updated&q=language:D").receiveAsRange();
    postContent("http://httpbin.org/post", stream);
}
```

You can use `dlang-requests` in parallel tasks (but you can't share the same `Request` structure between threads):

```d
import std.stdio;
import std.parallelism;
import std.algorithm;
import std.string;
import core.atomic;
import requests;

immutable auto urls = [
    "http://httpbin.org/stream/10",
    "http://httpbin.org/stream/20",
    "http://httpbin.org/stream/30",
    "http://httpbin.org/stream/40",
    "http://httpbin.org/stream/50",
    "http://httpbin.org/stream/60",
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

##### File download example #####

Note: use "wb" and `rawWrite` with file.

```d
import requests;
import std.stdio;

void main() {
    Request rq = Request();
    Response rs = rq.get("http://geoserver.readthedocs.io/en/latest/_images/imagemosaiccreate1.png");
    File f = File("123.png", "wb"); // do not forget to use both "w" and "b" modes when open file.
    f.rawWrite(rs.responseBody.data);
    f.close();
}
```
Loading whole document to memory and then save it might be impractical or impossible.
Use streams in this case:
```d
import requests;
import std.stdio;

void main() {
    Request rq = Request();

    rq.useStreaming = true;
    auto rs = rq.get("http://geoserver.readthedocs.io/en/latest/_images/imagemosaiccreate1.png");
    auto stream = rs.receiveAsRange();
    File file = File("123.png", "wb");

    while(!stream.empty)  {
        file.rawWrite(stream.front);
        stream.popFront;
    }
    file.close();
}
```


#### vibe.d ####

You can safely use `dlang-requests` with `vibe.d`. When `dlang-requests` is compiled with support for `vibe.d` sockets (`--config=vibed`), each call to `dlang-requests` API can block only the current fiber, not the thread:

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
```

Output:

```
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

### Adding/replacing request headers ###

Use `string[string]` and `addHeaders()` method to add or replace some request headers.

User-supplied headers override headers, created by library code,
so you have to be careful adding common headers, like Content-Type, Content-Length, etc..


```d
import requests;

void main() {
    auto rq = Request();
    rq.verbosity = 2;
    rq.addHeaders(["User-Agent": "test-123", "X-Header": "x-value"]);
    auto rs = rq.post("http://httpbin.org/post", `{"a":"b"}`, "application/x-www-form-urlencoded");
}
```

Output:

```
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

### SSL settings ###

HTTP requests can be configured for SSL options: you can enable or disable remote server certificate verification, set key and certificate to use for authorizing to remote server:

* sslSetVerifyPeer(bool) - turn ssl peer verification **on** or **off** (**on** by default since v0.8.0)
* sslSetKeyFile(string) - load client key from file
* sslSetCertFile(string) - load client cert from file
* sslSetCaCert(string) - load server CA cert for private or self-signed server certificates

```d
import std.stdio;
import requests;
import std.experimental.logger;

void main() {
    globalLogLevel(LogLevel.trace);
    auto rq = Request();
    rq.sslSetKeyFile("client01.key"); // set key file
    rq.sslSetCertFile("client01.crt"); // set cert file
    auto rs = rq.get("https://dlang.org/");
    writeln(rs.code);
    writeln(rs.responseBody);
}
```

Please note that with `vibe.d` you have to add the following call

```d
rq.sslSetCaCert("/opt/local/etc/openssl/cert.pem");
```

with path to CA cert file (location may differ for different OS or openssl packaging).

By default ssl peer verification turned ON. This can lead to problems in case you use server-side self-signed certificates.
To fix, you have either add server ca.crt to trusted store on local side(see https://unix.stackexchange.com/questions/90450/adding-a-self-signed-certificate-to-the-trusted-list for example), or use sslSetCaCert to add it for single requests call(`rq.sslSetCaCert("ca.crt");`), or just disable peer verification with
`rq.sslSetVerifyPeer(false);`

### FTP requests ###

You can use the same structure to make ftp requests, both get and post.

HTTP-specific methods do not work if request uses `ftp` scheme.

Here is an example:

```d
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

Second argument for FTP posts can be anything that can be casted to `ubyte[]` or any `InputRange` with element type like `ubyte[]`.
If the path in the post request doesn't exist, it will try to create all the required directories.
As with HTTP, you can call several FTP requests using the same `Request` structure - it will reuse established connection (and authorization as well).


### `Response` structure ###

This structure provides details about received response.

Most frequently needed parts of `Response` are:

* `code` - HTTP or FTP response code as received from server.
* `responseBody` - contain complete document body when no streaming is in use. You can't use it when in streaming mode.
* `responseHeaders` - response headers in form of `string[string]` (not available for FTP requests)
* `receiveAsRange` - if you set `useStreaming` in the `Request`, then `receiveAsRange` will provide elements (type `ubyte[]`) of `InputRange` while receiving data from the server.


### Requests Pool ###

When you have a large number of requests to execute, you can use a request pool to speed things up.

A `pool` is a fixed set of worker threads, which receives requests in form of `Job`s and returns `Result`s.

Each `Job` can be configured for an URL, method, data (for POST requests) and some other parameters.

`pool` acts as a parallel `map` from `Job` to `Result` - it consumes `InputRange` of `Job`s, and produces `InputRange` of `Result`s as fast as it can.

It is important to note that `pool` does not preserve result order. If you need to tie jobs and results somehow, you can use the `opaque` field of `Job`.

Here is an example usage:

```d
import std.algorithm;
import std.datetime;
import std.string;
import std.range;
import requests;

void main() {
    Job[] jobs = [
        Job("http://httpbin.org/get").addHeaders([
                            "X-Header": "X-Value",
                            "Y-Header": "Y-Value"
                        ]),
        Job("http://httpbin.org/gzip"),
        Job("http://httpbin.org/deflate"),
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
}
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
```

Output:

```
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

`Job` methods

| name        | parameter type             | description               |
|-------------|----------------------------|---------------------------|
| method      | `string` "GET" or "POST"   | request method            |
| data        | `immutable(ubyte)[]`       | data for POST request     |
| timeout     | `Duration`                 | timeout for network IO    |
| maxRedirects| `uint`                     | max. no. of redirects     |
| opaque      | `immutable(ubyte)[]`       | opaque data               |
| addHeaders  | `string[string]`           | headers to add to request |

`Result` fields

| name   | type                 | description          |
|--------|----------------------|----------------------|
| flags  | `uint`               | flags (OK,EXCEPTION) |
| code   | `ushort`             | response code        |
| data   | `immutable(ubyte)[]` | response body        |
| opaque | `immutable(ubyte)[]` | opaque data from job |


### Pool limitations ###

1. Currently it doesn't work under `vibe.d` - use `vibe.d` parallelisation.
1. It limits you in tuning request (e.g. you can add authorization only through `addHeaders()`, you can't tune SSL parameters, etc).
1. `Job`'s' and `Result`'s' `data` are immutable byte arrays (as it uses send/receive for data exchange).

#### International Domain names ####

dlang-requests supports IDNA through `idna` package.
It provide correct conversion between unicode domain names and punycode, but have limited ability to check names for standard compliance.
