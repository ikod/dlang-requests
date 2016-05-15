module requests.utils;

import std.range;

static immutable short[string] standard_ports;
static this() {
    standard_ports["http"] = 80;
    standard_ports["https"] = 443;
    standard_ports["ftp"] = 21;
}


auto getter(string name) {
    return `
        @property final auto ` ~ name ~ `() const @safe @nogc {
            return __` ~ name ~ `;
        }
    `;
}
auto setter(string name) {
    string member = "__" ~ name;
    string t = "typeof(this."~member~")";
    return `
        @property final void ` ~ name ~`(` ~ t ~ ` s) {`~ 
             member ~`=s;
        }
    `;
}

unittest {
    struct S {
        private {
            int    __i;
            string __s;
            bool   __b;
        }
        mixin(getter("i"));
        mixin(setter("i"));
        mixin(getter("b"));
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

