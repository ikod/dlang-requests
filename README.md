# dlang-requests

[![Build Status](https://travis-ci.org/ikod/dlang-requests.svg?branch=master)](https://travis-ci.org/ikod/dlang-requests)

HTTP requests library with goals:

* small memory footprint
* performance
* simple, high level API

API docs: [Wiki](https://github.com/ikod/dlang-requests/wiki)

In simplest scenario you just need to fetch and process document from remote site. In this case you can call getContent
```d
import std.stdio;
import std.algorithm;
import requests;

pragma(lib, "ssl");
pragma(lib, "crypto");

void main() {
    writeln(
        getContent("https://httpbin.org/")
        .splitter('\n')
        .filter!("a.length>0")
        .count
    );
}
```
getContent returns Buffer, filled with data. Buffer looks like Appender!ubyte (it have method data()), but also support many Range operations.

When you need access to response code, you have to use *Request* and *Response* structures:

```d
Request rq = Request();
Response rs = rq.get("https://httpbin.org/");
assert(rs.code==200);
```

For anything other than default, you can configure *Request* structure for keep-alive, redirects, headers, or for different io buffer and maximum sizes of response headers and body.

For example to authorize with Basic authorization use next code:
```c
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

Usage example:
```d
 auto rq = Request();
 auto rs = rq.get("http://httpbin.org/");
 writeln(rs.responseBody.data!string);

 rq.keepAlive = true;
 rs = rq.post("http://httpbin.org/post", `{"a":"b", "c":[1,2,3]}`, "application/json");
 assert(rs.code==200);

 auto f = File("tests/test.txt", "rb");
 rs = rq.post("http://httpbin.org/post", f.byChunk(3), "application/octet-stream");
 assert(rs.code==200);
 auto data = parseJSON(rs.responseBody.data).object["data"].str;
 assert(data=="abcdefgh\n12345678\n");
 f.close();

```


##### For Windows users
Requests distributed with binary ssl and crypto libraries. These libararies were downloaded from https://slproweb.com/products/Win32OpenSSL.html (full version) and converted using "implib /system" http://ftp.digitalmars.com/bup.zip.
If you know better way to link windows libraries, please, let me know.
