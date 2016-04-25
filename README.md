# dlang-requests
http requests library

[buildbadge]: https://travis-ci.org/ikod/dlang-requests.svg?branch=master
[buildstatus]: https://travis-ci.org/ikod/dlang-requests


Usage example:
```
 auto rq = Request();
 auto rs = rq.get("http://httpbin.org/");
 writeln(rs.responseBody.data!string);

 rq.keepAlive = 5;
 rs = rq.exec!"POST"("http://httpbin.org/post", `{"a":"b", "c":[1,2,3]}`, "application/json");
 assert(rs.code==200);

 auto f = File("tests/test.txt", "rb");
 rs = rq.exec!"POST"("http://httpbin.org/post", f.byChunk(3), "application/octet-stream");
 assert(rs.code==200);
 auto data = parseJSON(rs.responseBody.data).object["data"].str;
 assert(data=="abcdefgh\n12345678\n");
 f.close();

```
