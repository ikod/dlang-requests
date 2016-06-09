# dlang-requests

[![Build Status](https://travis-ci.org/ikod/dlang-requests.svg?branch=master)](https://travis-ci.org/ikod/dlang-requests)

HTTP requests library with goals:

* small memory footprint
* performance
* simple, high level API

API docs: [Wiki](https://github.com/ikod/dlang-requests/wiki)

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
    $ cat e.d; ./e
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

When you need access to response code, or configure request details you have to use *Request* and *Response* structures:

```d
Request rq = Request();
Response rs = rq.get("https://httpbin.org/");
assert(rs.code==200);
```

For anything other than default, you can configure *Request* structure for keep-alive, redirects, headers, o
r for different io-buffer and maximum sizes of response headers and body.

For example to authorize with Basic authorization use next code:
```d
    rq = Request();
    rq.authenticator = new BasicAuthentication("user", "passwd");
    rs = rq.get("http://httpbin.org/basic-auth/user/passwd");
```
Here is short descrition of some Request options:

| name             | type           | meaning                                | default    |
|------------------|----------------|----------------------------------------|------------|
| keepAlive        | bool           | request keepalive connection           | false      |
| maxRedirects     | uint           | maximum redirect depth                 | 10         |
| maxHeadersLength | size_t         | max.acceptable response headers length | 32KB       |
| maxContentLength | size_t         | max.acceptable content length          | 5MB        |
| timeout          | Duration       | timeout on connect or data transfer    | 30.seconds |
| bufferSize       | size_t         | socket io buffer size                  | 16KB       |
| verbosity        | uint           | verbosity level (0, 1 or 2)            | 0          |
| proxy            | string         | url of the http proxy                  | null       |
| headers          | string[string] | additional headers                     | null       |

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

