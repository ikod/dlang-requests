module request.utils;

static immutable short[string] standard_ports;
static this() {
    standard_ports["http"] = 80;
    standard_ports["https"] = 443;
}


auto getter(string name) {
    return `
        @property auto ` ~ name ~ `() const @safe @nogc {
            return __` ~ name ~ `;
        }
    `;
}
auto setter(string name) {
    string member = "__" ~ name;
    string t = "typeof(this."~member~")";
    return `
        @property void ` ~ name ~`(` ~ t ~ ` s) {`~ 
    member ~`=s;
        }
    `;
}

