module requests.utils;

import std.range;
import std.string;


__gshared immutable short[string] standard_ports;
shared static this() {
    standard_ports["http"] = 80;
    standard_ports["https"] = 443;
    standard_ports["ftp"] = 21;
}


string Getter_Setter(T)(string name) {
    return `
        @property final ` ~ T.stringof ~ ` ` ~ name ~ `() pure const @safe @nogc nothrow {
            return _` ~ name ~ `;
        }
        @property final void ` ~ name ~ `(` ~ T.stringof ~ ` s) pure @nogc nothrow { 
            _` ~ name ~ `=s;
        }
    `;
}

string Setter(T)(string name) {
    return `
        @property final void ` ~ name ~ `(` ~ T.stringof ~ ` s) pure @nogc nothrow { 
            _` ~ name ~ `=s;
        }
    `;
}

string Getter(T)(string name) {
    return `
        @property final ` ~ T.stringof ~ ` ` ~ name ~ `() pure const @safe @nogc nothrow {
            return _` ~ name ~ `;
        }
    `;
}

//auto getter(string name) {
//    return `
//        @property final auto ` ~ name ~ `() const @safe @nogc {
//            return __` ~ name ~ `;
//        }
//    `;
//}
//auto setter(string name) {
//    string member = "__" ~ name;
//    string t = "typeof(this."~member~")";
//    return `
//        @property final void ` ~ name ~`(` ~ t ~ ` s) pure @nogc nothrow {`~ 
//             member ~`=s;
//        }
//    `;
//}

unittest {
    struct S {
        private {
            int    _i;
            string _s;
            bool   _b;
        }
        mixin(Getter!int("i"));
        mixin(Setter!int("i"));
        mixin(Getter!bool("b"));
    }
    S s;
    assert(s.i == 0);
    s.i = 1;
    assert(s.i == 1);
    assert(s.b == false);
}

template rank(R) {
    static if ( isInputRange!R ) {
        enum size_t rank = 1 + rank!(ElementType!R);
    } else {
        enum size_t rank = 0;
    }
}
unittest {
    assert(rank!(char) == 0);
    assert(rank!(string) == 1);
    assert(rank!(ubyte[][]) == 2);
}
// test if p1 is sub-path of p2 (used to find Cookie to send)
bool pathMatches(string p1, string p2) pure @safe @nogc {
    import std.algorithm;
    return p1.startsWith(p2);
}

package unittest {
    assert("/abc/def".pathMatches("/"));
    assert("/abc/def".pathMatches("/abc"));
    assert("/abc/def".pathMatches("/abc/def"));
    assert(!"/def".pathMatches("/abc"));
}

// test if d1 is subbomain of d2 (used to find Cookie to send)
//    Host names can be specified either as an IP address or a HDN string.
//    Sometimes we compare one host name with another.  (Such comparisons
//    SHALL be case-insensitive.)  Host A's name domain-matches host B's if
//        
//    *  their host name strings string-compare equal; or
//    
//    * A is a HDN string and has the form NB, where N is a non-empty
//        name string, B has the form .B', and B' is a HDN string.  (So,
//            x.y.com domain-matches .Y.com but not Y.com.)
        
package bool domainMatches(string d1, string d2) pure @safe @nogc {
    import std.algorithm;
    return d1==d2 ||
           (d2[0] == '.' && d1.endsWith(d2));
}

package unittest {
    assert("x.example.com".domainMatches(".example.com"));
    assert(!"x.example.com".domainMatches("example.com"));
    assert("example.com".domainMatches("example.com"));
}

string[] dump(in ubyte[] data) {
    import std.stdio;
    import std.range;
    import std.ascii;
    import std.format;
    import std.algorithm;

    string[] res;

    foreach(i,chunk; data.chunks(16).enumerate) {
        string r;
        r ~= format("%05X  ", i*16);
        ubyte[] left, right;
        if ( chunk.length > 8 ) {
            left = chunk[0..8].dup;
            right= chunk[8..$].dup;
        } else {
            left = chunk.dup;
        }
        r ~= format("%-24.24s ", left.map!(c => format("%02X", c)).join(" "));
        r ~= format("%-24.24s ", right.map!(c => format("%02X", c)).join(" "));
        r ~= format("|%-16s|", chunk.map!(c => isPrintable(c)?cast(char)c:'.'));
        res ~= r;
    }
    return res;
}

static string urlEncoded(string p) pure @safe {
    immutable string[dchar] translationTable = [
        ' ':  "%20", '!': "%21", '*': "%2A", '\'': "%27", '(': "%28", ')': "%29",
        ';':  "%3B", ':': "%3A", '@': "%40", '&':  "%26", '=': "%3D", '+': "%2B",
        '$':  "%24", ',': "%2C", '/': "%2F", '?':  "%3F", '#': "%23", '[': "%5B",
        ']':  "%5D", '%': "%25",
    ];
    return p.translate(translationTable);
}
package unittest {
    assert(urlEncoded(`abc !#$&'()*+,/:;=?@[]`) == "abc%20%21%23%24%26%27%28%29%2A%2B%2C%2F%3A%3B%3D%3F%40%5B%5D");
}

private static immutable char[string] hex2chr;
static this() {
    foreach(c; 0..255) {
        hex2chr["%02X".format(c)] = cast(char)c;
    }
}

string urlDecode(string p) {
    import std.string;
    import std.algorithm;
    import core.exception;

    if ( !p.canFind("%") ) {
        return p.replace("+", " ");
    }
    string[] res;
    auto parts = p.replace("+", " ").split("%");
    res ~= parts[0];
    foreach(part; parts[1..$]) {
        if ( part.length<2 ) {
            res ~= "%" ~ part;
            continue;
        }
        try {
            res ~= hex2chr[part[0..2]] ~ part[2..$];
        } catch (RangeError e) {
            res ~= "%" ~ part;
        }
    }
    return res.join();
}

package unittest {
    assert(urlEncoded(`abc !#$&'()*+,/:;=?@[]`) == "abc%20%21%23%24%26%27%28%29%2A%2B%2C%2F%3A%3B%3D%3F%40%5B%5D");
    assert(urlDecode("a+bc%20%21%23%24%26%27%28%29%2A%2B%2C%2F%3A%3B%3D%3F%40%5B%5D") == `a bc !#$&'()*+,/:;=?@[]`);
}

import std.typecons;

public alias Cookie     = Tuple!(string, "path", string, "domain", string, "attr", string, "value");
public alias QueryParam = Tuple!(string, "key", string, "value");
