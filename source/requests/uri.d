module requests.uri;

import std.experimental.logger;
import std.array;
import std.format;
import std.algorithm;
import std.conv;
import requests.utils;

class UriException: Exception {
    this(string msg, string file = __FILE__, size_t line = __LINE__) @safe pure {
        super(msg, file, line);
    }
}

struct URI {
    import std.string;
    private {
        string _uri;
        string _scheme;
        string _username;
        string _password;
        ushort _port=80;
        string _host;
        string _path="/";
        string _query;
    }
    this(string uri) @safe pure {
        _uri = uri;
        auto parsed = uri_parse(uri);
        if ( !parsed ) {
            throw new UriException("Can't parse uri '" ~ _uri ~ "'");
        }
    }
    
    bool uri_parse(string uri) @safe pure {
        auto i = uri.findSplit("://");
        string   rest;
        if ( i[1].length ) {
            _scheme = i[0].toLower;
            rest = i[2];
        } else {
            return false;
        }
        // separate Authority from path and query
        i = rest.findSplit("/");
        auto authority = i[0];
        auto path_and_query = i[2];
        
        // find user/password/host:port in authority
        i = authority.findSplit("@");
        string up;
        string hp;
        if ( i[1].length ) {
            up = i[0];
            hp = i[2];
        } else {
            hp = i[0];
        }

        i = hp.findSplit(":");
        _host = i[0];
        _port = i[2].length ? to!ushort(i[2]) : standard_ports[_scheme];

        if ( up.length ) {
            i = up.findSplit(":");
            _username = i[0];
            _password = i[2];
        }
        // finished with authority
        // handle path and query
        if ( path_and_query.length ) {
            i = path_and_query.findSplit("?");
            _path = "/" ~ i[0];
            if ( i[2].length) {
                _query = "?" ~ i[2];
            }
        }
        //
        return true;
    }
    
    string recalc_uri() const pure @safe {
        string userinfo;
        if ( _username ) {
            userinfo = "%s".format(_username);
            if ( _password ) {
                userinfo ~= ":" ~ _password;
            }
            userinfo ~= "@";
        }
        string r = "%s://%s%s".format(_scheme, userinfo, _host);
        if ( _scheme !in standard_ports || standard_ports[_scheme] != _port ) {
            r ~= ":%d".format(_port);
        }
        r ~= _path;
        if ( _query ) {
            r ~= _query;
        }
        return r;
    }
    mixin(Getter_Setter!string("scheme"));
    mixin(Getter_Setter!string("host"));
    mixin(Getter_Setter!string("username"));
    mixin(Getter_Setter!string("password"));
    mixin(Getter_Setter!ushort("port"));
    mixin(Getter_Setter!string("path"));
    mixin(Getter!string("query"));
    @property void query(string s) {
        if ( s[0]=='?' ) {
            _query = s;
        }
        else {
            _query = "?" ~ s;
        }
    }
//    mixin(setter("scheme"));
//    mixin(setter("host"));
//    mixin(setter("username"));
//    mixin(setter("password"));
//    mixin(setter("port"));
//    mixin(setter("path"));
//    mixin(setter("query"));
    @property auto uri() pure @safe const {
        return recalc_uri();
    }
    @property void uri(string s) @trusted {
        _uri = s;
        //        auto parsed = uri_grammar(s);
        //        if ( !parsed.successful || parsed.matches.joiner.count != __uri.length) {
        //            throw new UriException("Can't parse uri '" ~ __uri ~ "'");
        //        }
        //        traverseTree(parsed);
    }
}
unittest {
    import std.exception;
    import std.experimental.logger;
    
    globalLogLevel(LogLevel.info);
    auto a = URI("http://example.com/");
    assert(a.scheme == "http");
    assert(a.host == "example.com");
    assert(a.path == "/");
    a = URI("svn+ssh://igor@example.com:1234");
    assert(a.scheme == "svn+ssh");
    assert(a.host == "example.com");
    assert(a.username == "igor");
    assert(a.path == "/");
    a = URI("http://igor:pass;word@example.com:1234/abc?q=x");
    assert(a.password == "pass;word");
    assert(a.port == 1234);
    assert(a.path == "/abc");
    assert(a.query == "?q=x");
    a.scheme = "https";
    a.query = "x=y";
    a.port = 345;
    auto expected = "https://igor:pass;word@example.com:345/abc?x=y";
    assert(a.uri == expected, "Expected '%s', got '%s'".format(expected, a.uri));
    assertThrown!UriException(URI("@unparsable"));
}

