module httpbin;

version(vibeD) {
} else
version (unittest) {
	import requests.server;
	import requests.utils;
	import std.datetime;
	import std.json;
	import std.conv;
	import std.range;
	import std.string;
	import core.thread;

	auto buildReply(ref HTTPD_Request rq) {
		auto method  = JSONValue(rq.method);
		auto args    = JSONValue(rq.query);
		auto headers = JSONValue(rq.requestHeaders);
		auto url     = JSONValue(rq.uri.uri);
		auto json    = JSONValue(parseJSON(rq.json));
		auto data    = JSONValue(rq.data);
		auto form    = JSONValue(rq.form);
		auto files   = JSONValue(rq.files);
		auto reply   = JSONValue([
				"method": method,
				"headers": headers, 
				"args":args,
				"json": json, 
				"url": url, 
				"data": data, 
				"form": form, 
				"files": files
			]);
		return reply.toString();
	}

	HTTPD httpbinApp() {
	    pragma(msg, "Compiling httpbin server");

		HTTPD server = new HTTPD();
		App httpbin = App("httpbin");
		
		httpbin.port = 8081;
		httpbin.host = "0.0.0.0"; 
		httpbin.timeout = 10.seconds;
		server.app(httpbin);

		auto root(in App app, ref HTTPD_Request rq, Route ro) {
			debug (httpd) trace("handler / called");
			auto rs = response(rq, buildReply(rq));
			rs.headers["Content-Type"] = "application/json";
			return rs;
		}
		auto get(in App app, ref HTTPD_Request rq, Route ro) {
			debug (httpd) trace("handler /get called");
			auto rs = response(rq, buildReply(rq));
			rs.headers["Content-Type"] = "application/json";
			return rs;
		}
		auto del(in App app, ref HTTPD_Request rq, Route ro) {
			if ( rq.method != "DELETE") {
				auto rs = response(rq, "Illegal method %s".format(rq.method), 405);
				return rs;
			}
			else {
				auto rs = response(rq, buildReply(rq));
				return rs;
			}
		}
		auto put(in App app, ref HTTPD_Request rq, Route ro) {
			if ( rq.method != "PUT") {
				auto rs = response(rq, "Illegal method %s".format(rq.method), 405);
				return rs;
			}
			else {
				auto rs = response(rq, buildReply(rq));
				return rs;
			}
		}
		auto patch(in App app, ref HTTPD_Request rq, Route ro) {
			if ( rq.method != "PATCH") {
				auto rs = response(rq, "Illegal method %s".format(rq.method), 405);
				return rs;
			}
			else {
				auto rs = response(rq, buildReply(rq));
				return rs;
			}
		}
		auto post(in App app, ref HTTPD_Request rq, Route ro) {
			auto rs = response(rq, buildReply(rq));
			return rs;
		}
		auto gzip(in App app, ref HTTPD_Request rq, Route ro) {
			auto content = ["gzipped":true];
			auto rs = response(rq, JSONValue(content).toPrettyString);
			rs.compress(Compression.gzip);
			rs.headers["Content-Type"] = "application/json";
			return rs;
		}
		auto deflate(in App app, ref HTTPD_Request rq, Route ro) {
			auto content = ["deflated":true];
			auto rs = response(rq, JSONValue(content).toPrettyString);
			rs.compress(Compression.deflate);
			return rs;
		}
		auto rel_redir(in App app, ref HTTPD_Request rq, Route ro) {
			auto rs = response(rq, buildReply(rq));
			auto redirects = to!long(ro.captures["redirects"]);
			if ( redirects > 1 ) {
				rs.headers["Location"] = "/relative-redirect/%d".format(redirects-1);
			} else {
				rs.headers["Location"] = "/get";
			}
			rs.status    = 302;
			return rs;
		}
		auto abs_redir(in App app, ref HTTPD_Request rq, Route ro) {
			auto rs = response(rq, buildReply(rq));
			auto redirects = to!long(ro.captures["redirects"]);
			if ( redirects > 1 ) {
				rs.headers["Location"] = "http://localhost:8081/absolute-redirect/%d".format(redirects-1);
			} else {
				rs.headers["Location"] = "http://localhost:8081/get";
			}
			rs.status    = 302;
			return rs;
		}
		auto cookiesSet(in App app, ref HTTPD_Request rq, Route ro) {
			Cookie[] cookies;
			foreach(p; rq.query.byKeyValue) {
				cookies ~= Cookie("/cookies", rq.requestHeaders["host"], p.key, p.value);
			}
			auto rs = response(rq, buildReply(rq), 302);
			rs.headers["Location"] = "/cookies";
			rs.cookies = cookies;
			return rs;
		}
		auto cookies(in App app, ref HTTPD_Request rq, Route ro) {
			auto cookies = ["cookies": JSONValue(rq.cookies)];
			auto rs = response(rq, JSONValue(cookies).toString);
			return rs;
		}
		auto range(in App app, ref HTTPD_Request rq, Route ro) {
			auto size = to!long(ro.captures["size"]);
			auto rs = response(rq, new ubyte[size].chunks(16));
			rs.compress(Compression.yes);
			return rs;
		}
		auto basicAuth(in App app, ref HTTPD_Request rq, Route ro) {
			import std.base64;
			auto user    = ro.captures["user"];
			auto password= ro.captures["password"];
			auto auth    = cast(string)Base64.decode(rq.requestHeaders["authorization"].split()[1]);
			auto up      = auth.split(":");
			short status;
			if ( up[0]==user && up[1]==password) {
				status = 200;
			} else {
				status = 401;
			}
			auto rs = response(rq, buildReply(rq), status);
			rs.headers["Content-Type"] = "application/json";
			return rs;
		}
		auto delay(in App app, ref HTTPD_Request rq, Route ro) {
			auto delay = dur!"seconds"(to!long(ro.captures["delay"]));
			Thread.sleep(delay);
			auto rs = response(rq, buildReply(rq));
			rs.headers["Content-Type"] = "application/json";
			return rs;
		}
		auto stream(in App app, ref HTTPD_Request rq, Route ro) {
			auto lines = to!long(ro.captures["lines"]);
			auto rs = response(rq, (buildReply(rq) ~ "\n").repeat(lines));
			rs.headers["Content-Type"] = "application/json";
			return rs;
		}
		server.addRoute(exactRoute(r"/",             &root)).
				addRoute(exactRoute(r"/get",         &get)).
				addRoute(exactRoute(r"/post",        &post)).
				addRoute(exactRoute(r"/delete",      &del)).
				addRoute(exactRoute(r"/put",         &put)).
				addRoute(exactRoute(r"/patch",       &patch)).
				addRoute(exactRoute(r"/cookies",     &cookies)).
				addRoute(exactRoute(r"/cookies/set", &cookiesSet)).
				addRoute(exactRoute(r"/gzip",        &gzip)).
				addRoute(exactRoute(r"/deflate",     &deflate)).
				addRoute(regexRoute(r"/delay/(?P<delay>\d+)",  &delay)).
				addRoute(regexRoute(r"/stream/(?P<lines>\d+)", &stream)).
				addRoute(regexRoute(r"/range/(?P<size>\d+)",   &range)).
				addRoute(regexRoute(r"/relative-redirect/(?P<redirects>\d+)", &rel_redir)).
				addRoute(regexRoute(r"/absolute-redirect/(?P<redirects>\d+)", &abs_redir)).
				addRoute(regexRoute(r"/basic-auth/(?P<user>[^/]+)/(?P<password>[^/]+)", &basicAuth));

		return server;
	}
}
