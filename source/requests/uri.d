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
        string __uri;
        string __scheme;
        string __username;
        string __password;
        ushort  __port=80;
        string __host;
        string __path="/";
        string __query;
    }
    this(string uri) {
        __uri = uri;
        auto parsed = uri_parse(uri);
        if ( !parsed ) {
            throw new UriException("Can't parse uri '" ~ __uri ~ "'");
        }
    }
    
    bool uri_parse(string uri) {
        auto i = uri.findSplit("://");
        string   rest;
        if ( i[1].length ) {
            __scheme = i[0].toLower;
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
        __host = i[0];
        if ( i[2].length ) {
            __port = to!ushort(i[2]);
        } else {
            if ( __scheme == "https" ) {
                __port = 443;
            }
        }
        if ( up.length ) {
            i = up.findSplit(":");
            __username = i[0];
            __password = i[2];
        }
        // finished with authority
        // handle path and query
        if ( path_and_query.length ) {
            i = path_and_query.findSplit("?");
            __path = "/" ~ i[0];
            if ( i[2].length) {
                __query = "?" ~ i[2];
            }
        }
        //
        return true;
    }
    
    string recalc_uri() const pure @safe {
        string userinfo;
        if ( __username ) {
            userinfo = "%s".format(__username);
            if ( __password ) {
                userinfo ~= ":" ~ __password;
            }
            userinfo ~= "@";
        }
        string r = "%s://%s%s".format(__scheme, userinfo, __host);
        if ( __scheme !in standard_ports || standard_ports[__scheme] != __port ) {
            r ~= ":%d".format(__port);
        }
        r ~= __path;
        if ( __query ) {
            r ~= "?" ~ __query;
        }
        return r;
    }
    mixin(getter("scheme"));
    mixin(getter("host"));
    mixin(getter("username"));
    mixin(getter("password"));
    mixin(getter("port"));
    mixin(getter("path"));
    mixin(getter("query"));
    
    mixin(setter("scheme"));
    mixin(setter("host"));
    mixin(setter("username"));
    mixin(setter("password"));
    mixin(setter("port"));
    mixin(setter("path"));
    mixin(setter("query"));
    @property auto uri() pure @safe const {
        return recalc_uri();
    }
    @property void uri(string s) @trusted {
        __uri = s;
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

//struct sURI {
//    import pegged.grammar;
//    mixin(grammar(`
//            uri_grammar:
//                Uri <- Scheme '://' Authority ( Path ( '?' Query )? )?
//                Scheme <- alpha ( alpha / digit / '+' / '-' / '.')*
//                Authority <- ( Userinfo '@')? Host (':' Port)?
//                Userinfo <- ( Unreserved / PCT / SubDelims / ':' )*
//                Path <- ('/' Pchar* )*
//                Query <- ( Pchar / '/' / '?' )*
//                Host <- RegName
//                Port < digit+
//                RegName <- ( Unreserved / PCT / SubDelims )+
//                Unreserved <- alpha / Alpha / digit / '-' / '.' / '_' / '~'
//                PCT <- '%' hexDigit hexDigit
//                Pchar <- Unreserved / PCT / SubDelims / ':' / '@'
//                SubDelims <- '!' / 
//                             '$' / 
//                             '&' / 
//                             '\'' / 
//                             '(' / ')' / 
//                             '*' / '+' / ',' / ';' / '='
//          `));
//    private {
//        string __uri;
//        string __scheme;
//        string __username;
//        string __password;
//        ushort  __port=80;
//        string __host;
//        string __path="/";
//        string __query;
//    }
//    void traverseTree(ParseTree tree) {
//        foreach(ref child; tree.children) {
//            traverseTree(child);
//        }
//        switch(tree.name) {
//            case "uri_grammar.Scheme":
//                tracef("Scheme '%s'", tree.matches.join);
//                __scheme = tree.matches.join;
//                if ( __scheme == "https" ) {
//                    __port = 443;
//                }
//                break;
//            case "uri_grammar.Userinfo":
//                tracef("Userinfo '%s'", tree.matches.join);
//                auto p = tree.matches.findSplit([":"]);
//                __username = p[0].join;
//                __password = p[2].join;
//                break;
//            case "uri_grammar.Host":
//                tracef("Host '%s'", tree.matches.join);
//                __host = tree.matches.join;
//                break;
//            case "uri_grammar.Port":
//                tracef("Port '%s'", tree.matches.join);
//                __port = std.conv.to!ushort(tree.matches.join);
//                break;
//            case "uri_grammar.Path":
//                tracef("Path '%s'", tree.matches.join);
//                __path = tree.matches.join;
//                break;
//            case "uri_grammar.Query":
//                tracef("Query '%s'", tree.matches.join);
//                __query = "?" ~ tree.matches.join;
//                break;
//            default:
//        }
//    }
//    this(string uri) {
//        __uri = uri;
//        auto parsed = uri_grammar(uri);
//        if ( !parsed.successful || parsed.matches.joiner.count != __uri.length) {
//            throw new UriException("Can't parse uri '" ~ __uri ~ "'");
//        }
//        traverseTree(parsed);
//    }
//    string recalc_uri() const pure @safe {
//        string userinfo;
//        if ( __username ) {
//            userinfo = "%s".format(__username);
//            if ( __password ) {
//                userinfo ~= ":" ~ __password;
//            }
//            userinfo ~= "@";
//        }
//        string r = "%s://%s%s".format(__scheme, userinfo, __host);
//        if ( __scheme !in standard_ports || standard_ports[__scheme] != __port ) {
//            r ~= ":%d".format(__port);
//        }
//        r ~= __path;
//        if ( __query ) {
//            r ~= "?" ~ __query;
//        }
//        return r;
//    }
//    mixin(getter("scheme"));
//    mixin(getter("host"));
//    mixin(getter("username"));
//    mixin(getter("password"));
//    mixin(getter("port"));
//    mixin(getter("path"));
//    mixin(getter("query"));
//    
//    mixin(setter("scheme"));
//    mixin(setter("host"));
//    mixin(setter("username"));
//    mixin(setter("password"));
//    mixin(setter("port"));
//    mixin(setter("path"));
//    mixin(setter("query"));
//    @property auto uri() pure @safe const {
//        return recalc_uri();
//    }
//    @property void uri(string s) @trusted {
//        __uri = s;
//        auto parsed = uri_grammar(s);
//        if ( !parsed.successful || parsed.matches.joiner.count != __uri.length) {
//            throw new UriException("Can't parse uri '" ~ __uri ~ "'");
//        }
//        traverseTree(parsed);
//    }
//}
//unittest {
//    import std.exception;
//    import std.experimental.logger;
//    
//    globalLogLevel(LogLevel.trace);
//    auto a = sURI("http://exampe.com/");
//    assert(a.scheme == "http");
//    a = sURI("svn+ssh://igor@example.com:1234");
//    assert(a.scheme == "svn+ssh");
//    assert(a.host == "example.com");
//    assert(a.username == "igor");
//    assert(a.path == "/");
//    a = sURI("http://igor:pass;word@example.com:1234/abc?q=x");
//    assert(a.password == "pass;word");
//    assert(a.port == 1234);
//    assert(a.path == "/abc");
//    assert(a.query == "?q=x");
//    a.scheme = "https";
//    a.query = "x=y";
//    a.port = 345;
//    auto expected = "https://igor:pass;word@example.com:345/abc?x=y";
//    assert(a.uri == expected, "Expected '%s', got '%s'".format(expected, a.uri));
//    assertThrown!UriException(URI("@unparsable"));
//}
