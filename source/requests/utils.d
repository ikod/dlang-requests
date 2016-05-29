module requests.utils;

import std.range;

static immutable short[string] standard_ports;
static this() {
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
