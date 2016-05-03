# dlang-requests
http requests library

[![Build Status](https://travis-ci.org/ikod/dlang-requests.svg?branch=master)](https://travis-ci.org/ikod/dlang-requests)

API docs: [Wiki](https://github.com/ikod/dlang-requests/wiki)

In simplest scenario you just need to fetch document from remote site. In this case you can just call getContent
```d
    auto r = getContent("https://httpbin.org/stream/20");
    assert(r.splitter('\n').filter!("a.length>0").count == 20);
```
getContent returns Buffer, filled with data. Buffer looks like Appender!ubyte (it have method data()),
but also support Range operations.

For anything other than default you can use Request structure, which can be configured for keep-alive, compressed requests,
for different io buffer and maximum sizes of response headers and body.

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
