module requests.ssl_adapter;

import std.stdio;
import std.string;
import std.format;
import std.typecons;
import core.stdc.stdlib;
import core.sys.posix.dlfcn;
import std.experimental.logger;

version(Windows) {
    import core.sys.windows.windows;
    alias DLSYM = GetProcAddress;
} else {
    alias DLSYM = dlsym;
}

/*
 * /usr/include/openssl/tls1.h:# define TLS_ANY_VERSION 0x10000
 */

immutable int TLS_ANY_VERSION = 0x10000;
immutable int TLS1_VERSION = 0x0301;
immutable int TLS1_2_VERSION = 0x0303;

struct SSL {};
struct SSL_CTX {};
struct SSL_METHOD {};

string SSL_Function_decl(string N, R, A...)() {
    string F = "extern (C) %s function %s adapter_%s;".format(R.stringof, A.stringof, N);
    return F;
}
string SSL_Function_set_i(string N, R, A...)() {
    string F = "openssl.adapter_%s = cast(typeof(openssl.adapter_%s))DLSYM(cast(void*)openssl._libssl, \"%s\");".format(N, N, N);
    return F;
}
string CRYPTO_Function_set_i(string N, R, A...)() {
    string F = "openssl.adapter_%s = cast(typeof(openssl.adapter_%s))DLSYM(cast(void*)openssl._libcrypto, \"%s\");".format(N, N, N);
    return F;
}

private alias Version = Tuple!(int, "major", int, "minor");

immutable static OpenSSL openssl;

static this() {
    if ( openssl._libssl !is null ) {
        return;
    }
    version(OSX) {
        openssl._libssl = cast(typeof(openssl._libssl))dlopen("libssl.dylib", RTLD_LAZY);
        openssl._libcrypto = cast(typeof(openssl._libcrypto))dlopen("libcrypto.dylib", RTLD_LAZY);
    } else
    version(linux) {
        openssl._libssl = cast(typeof(openssl._libssl))dlopen("libssl.so", RTLD_LAZY);
        openssl._libcrypto = cast(typeof(openssl._libcrypto))dlopen("libcrypto.so", RTLD_LAZY);
    } else
    version(Windows) {
        openssl._libssl = cast(typeof(openssl._libssl))LoadLibrary("libssl32.dll");
        openssl._libcrypto = cast(typeof(openssl._libcrypto))LoadLibrary("libeay32.dll");
    } else {
        throw new Exception("loading openssl: unsupported system");
    }
    if ( openssl._libssl is null ) {
        error("warning: failed to load libssl - first access over https will fail");
        return;
    }
    if ( openssl._libcrypto is null ) {
        error("warning: failed to load libcrypto - first access over https will fail");
        return;
    }
    openssl._ver = openssl.OpenSSL_version_detect();

    mixin(SSL_Function_set_i!("SSL_library_init", int));
    mixin(CRYPTO_Function_set_i!("OpenSSL_add_all_ciphers", void));
    mixin(CRYPTO_Function_set_i!("OpenSSL_add_all_digests", void));
    mixin(SSL_Function_set_i!("SSL_load_error_strings", void));

    mixin(SSL_Function_set_i!("OPENSSL_init_ssl", int, ulong, void*));
    mixin(CRYPTO_Function_set_i!("OPENSSL_init_crypto", int, ulong, void*));

    mixin(SSL_Function_set_i!("TLSv1_client_method", SSL_METHOD*));
    mixin(SSL_Function_set_i!("TLSv1_2_client_method", SSL_METHOD*));
    mixin(SSL_Function_set_i!("TLS_method", SSL_METHOD*));
    mixin(SSL_Function_set_i!("SSLv23_client_method", SSL_METHOD*));
    mixin(SSL_Function_set_i!("SSL_CTX_new", SSL_CTX*, SSL_METHOD*));
    mixin(SSL_Function_set_i!("SSL_CTX_set_default_verify_paths", int, SSL_CTX*));
    mixin(SSL_Function_set_i!("SSL_CTX_load_verify_locations", int, SSL_CTX*, char*, char*));
    mixin(SSL_Function_set_i!("SSL_CTX_set_verify", void, SSL_CTX*, int, void*));
    mixin(SSL_Function_set_i!("SSL_CTX_use_PrivateKey_file", int, SSL_CTX*, const char*, int));
    mixin(SSL_Function_set_i!("SSL_CTX_use_certificate_file", int, SSL_CTX*, const char*, int));
    mixin(SSL_Function_set_i!("SSL_CTX_set_cipher_list", int, SSL_CTX*, const char*));
    mixin(SSL_Function_set_i!("SSL_CTX_ctrl", long, SSL_CTX*, int, long, void*));
    mixin(SSL_Function_set_i!("SSL_new", SSL*, SSL_CTX*));
    mixin(SSL_Function_set_i!("SSL_set_fd", int, SSL*, int));
    mixin(SSL_Function_set_i!("SSL_connect", int, SSL*));
    mixin(SSL_Function_set_i!("SSL_write", int, SSL*, const void*, int));
    mixin(SSL_Function_set_i!("SSL_read", int, SSL*, void*, int));
    mixin(SSL_Function_set_i!("SSL_free", void, SSL*));
    mixin(SSL_Function_set_i!("SSL_CTX_free", void, SSL_CTX*));
    mixin(SSL_Function_set_i!("SSL_get_error", int, SSL*, int));
    mixin(SSL_Function_set_i!("SSL_ctrl", long, SSL*, int, long, void*));
    mixin(SSL_Function_set_i!("ERR_reason_error_string", char*, ulong));
    mixin(SSL_Function_set_i!("ERR_get_error", ulong));

    void delegate()[Version] init_matrix;
    init_matrix[Version(1,0)] = &openssl.init1_0;
    init_matrix[Version(1,1)] = &openssl.init1_1;
    auto init = init_matrix.get(openssl._ver, null);
    if ( init is null ) {
        throw new Exception("loading openssl: unknown version for init");
    }
    init();
    debug(requests) {
        if ( openssl.adapter_TLSv1_2_client_method is null ) {
            warning("WARNING: your SSL library do not support TLS1.2");
        }
    }
}

struct OpenSSL {

    private {
        Version         _ver;
        void*           _libssl;
        void*           _libcrypto;

        // openssl 1.0.x init functions
        mixin(SSL_Function_decl!("SSL_library_init", int));
        mixin(SSL_Function_decl!("OpenSSL_add_all_ciphers", void));
        mixin(SSL_Function_decl!("OpenSSL_add_all_digests", void));
        mixin(SSL_Function_decl!("SSL_load_error_strings", void));

        // openssl 1.1.x init functions
        mixin(SSL_Function_decl!("OPENSSL_init_ssl", int, ulong, void*));
        mixin(SSL_Function_decl!("OPENSSL_init_crypto", int, ulong, void*));

        // all other functions
        mixin(SSL_Function_decl!("TLSv1_client_method", SSL_METHOD*));
        mixin(SSL_Function_decl!("TLSv1_2_client_method", SSL_METHOD*));
        mixin(SSL_Function_decl!("TLS_method", SSL_METHOD*));
        mixin(SSL_Function_decl!("SSLv23_client_method", SSL_METHOD*));
        mixin(SSL_Function_decl!("SSL_CTX_new", SSL_CTX*, SSL_METHOD*));
        mixin(SSL_Function_decl!("SSL_CTX_set_default_verify_paths", int, SSL_CTX*));
        mixin(SSL_Function_decl!("SSL_CTX_load_verify_locations", int, SSL_CTX*, char*, char*));
        mixin(SSL_Function_decl!("SSL_CTX_set_verify", void, SSL_CTX*, int, void*));
        mixin(SSL_Function_decl!("SSL_CTX_use_PrivateKey_file", int, SSL_CTX*, const char*, int));
        mixin(SSL_Function_decl!("SSL_CTX_use_certificate_file", int, SSL_CTX*, const char*, int));
        mixin(SSL_Function_decl!("SSL_CTX_set_cipher_list", int, SSL_CTX*, const char*));
        mixin(SSL_Function_decl!("SSL_CTX_ctrl", long, SSL_CTX*, int, long, void*));
        mixin(SSL_Function_decl!("SSL_new", SSL*, SSL_CTX*));
        mixin(SSL_Function_decl!("SSL_set_fd", int, SSL*, int));
        mixin(SSL_Function_decl!("SSL_connect", int, SSL*));
        mixin(SSL_Function_decl!("SSL_write", int, SSL*, const void*, int));
        mixin(SSL_Function_decl!("SSL_read", int, SSL*, void*, int));
        mixin(SSL_Function_decl!("SSL_free", void, SSL*));
        mixin(SSL_Function_decl!("SSL_CTX_free", void, SSL_CTX*));
        mixin(SSL_Function_decl!("SSL_get_error", int, SSL*, int));
        mixin(SSL_Function_decl!("SSL_ctrl", long, SSL*, int, long, void*));
        mixin(SSL_Function_decl!("ERR_reason_error_string", char*, ulong));
        mixin(SSL_Function_decl!("ERR_get_error", ulong));
    }

    Version reportVersion() const @nogc nothrow pure {
        return _ver;
    };

    private Version OpenSSL_version_detect() const {
        ulong function() OpenSSL_version_num = cast(ulong function())DLSYM(cast(void*)_libcrypto, "OpenSSL_version_num".ptr);
        if ( OpenSSL_version_num ) {
            auto v = OpenSSL_version_num() & 0xffffffff;
            return Version((v>>>20) & 0xff, (v>>>28) & 0xff);
        }
        return Version(1, 0);
    }

    private void init1_0() const {
        adapter_SSL_library_init();
        adapter_OpenSSL_add_all_ciphers();
        adapter_OpenSSL_add_all_digests();
        adapter_SSL_load_error_strings();
    }
    private void init1_1() const {
        /**
        Standard initialisation options

        #define OPENSSL_INIT_LOAD_SSL_STRINGS       0x00200000L

        # define OPENSSL_INIT_LOAD_CRYPTO_STRINGS    0x00000002L
        # define OPENSSL_INIT_ADD_ALL_CIPHERS        0x00000004L
        # define OPENSSL_INIT_ADD_ALL_DIGESTS        0x00000008L
        **/
        enum OPENSSL_INIT_LOAD_SSL_STRINGS = 0x00200000L;
        enum OPENSSL_INIT_LOAD_CRYPTO_STRINGS = 0x00000002L;
        enum OPENSSL_INIT_ADD_ALL_CIPHERS = 0x00000004L;
        enum OPENSSL_INIT_ADD_ALL_DIGESTS = 0x00000008L;
        adapter_OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, null);
        adapter_OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, null);
    }

    SSL_METHOD* TLSv1_client_method() const {
        if ( adapter_TLSv1_client_method is null ) {
            throw new Exception("openssl not initialized - is it installed?");
        }
        return adapter_TLSv1_client_method();
    }
    SSL_METHOD* TLSv1_2_client_method() const {
        if ( adapter_TLSv1_2_client_method is null ) {
            throw new Exception("openssl not initialized - is it installed?");
        }
        return adapter_TLSv1_2_client_method();
    }
    SSL_METHOD* TLS_method() const {
        if ( adapter_TLS_method !is null ) {
            return adapter_TLS_method();
        }
        if ( adapter_SSLv23_client_method !is null ) {
            return adapter_SSLv23_client_method();
        }
        throw new Exception("can't complete call to TLS_method");
    }
    SSL_METHOD* SSLv23_client_method() const {
        if ( adapter_SSLv23_client_method is null ) {
            throw new Exception("can't complete call to SSLv23_client_method");
        }
        return adapter_SSLv23_client_method();
    }
    SSL_CTX* SSL_CTX_new(SSL_METHOD* method) const {
        if ( adapter_SSL_CTX_new is null ) {
            throw new Exception("openssl not initialized - is it installed?");
        }
        return adapter_SSL_CTX_new(method);
    }
    int SSL_CTX_set_default_verify_paths(SSL_CTX* ctx) const {
        return adapter_SSL_CTX_set_default_verify_paths(ctx);
    }
    int SSL_CTX_load_verify_locations(SSL_CTX* ctx, char* CAFile, char* CAPath) const {
        return adapter_SSL_CTX_load_verify_locations(ctx, CAFile, CAPath);
    }
    void SSL_CTX_set_verify(SSL_CTX* ctx, int mode, void* callback) const {
        adapter_SSL_CTX_set_verify(ctx, mode, callback);
    }
    int SSL_CTX_use_PrivateKey_file(SSL_CTX* ctx, const char* file, int type) const {
        return adapter_SSL_CTX_use_PrivateKey_file(ctx, file, type);
    }
    int SSL_CTX_use_certificate_file(SSL_CTX* ctx, const char* file, int type) const {
        return adapter_SSL_CTX_use_certificate_file(ctx, file, type);
    }
    int SSL_CTX_set_cipher_list(SSL_CTX* ssl_ctx, const char* c) const {
        return adapter_SSL_CTX_set_cipher_list(ssl_ctx, c);
    }
    /*
     *
     * # define SSL_CTRL_SET_MIN_PROTO_VERSION          123
     * # define SSL_CTRL_SET_MAX_PROTO_VERSION          124
    */
    enum int SSL_CTRL_SET_MIN_PROTO_VERSION = 123;
    enum int SSL_CTRL_SET_MAX_PROTO_VERSION = 124;
    int SSL_CTX_set_min_proto_version(SSL_CTX* ctx, int v) const {
        int r = cast(int)adapter_SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, cast(long)v, null);
        return r;
    }
    int SSL_CTX_set_max_proto_version(SSL_CTX* ctx, int v) const {
        int r = cast(int)adapter_SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, cast(long)v, null);
        return r;
    }
    SSL* SSL_new(SSL_CTX* ctx) const {
        return adapter_SSL_new(ctx);
    }
    int SSL_set_fd(SSL* ssl, int fd) const {
        return adapter_SSL_set_fd(ssl, fd);
    }
    int SSL_connect(SSL* ssl) const {
        return adapter_SSL_connect(ssl);
    }
    int SSL_read(SSL* ssl, void *b, int n) const {
        return adapter_SSL_read(ssl, b, n);
    }
    int SSL_write(SSL* ssl, const void *b, int n) const {
        return adapter_SSL_write(ssl, b, n);
    }
    void SSL_free(SSL* ssl) const {
        adapter_SSL_free(ssl);
    }
    void SSL_CTX_free(SSL_CTX* ctx) const {
        adapter_SSL_CTX_free(ctx);
    }
    int SSL_get_error(SSL* ssl, int err) const {
        return adapter_SSL_get_error(ssl, err);
    }
    long SSL_set_tlsext_host_name(SSL* ssl, const char* host) const {
        enum int SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;
        enum long TLSEXT_NAMETYPE_host_name = 0;
        return adapter_SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME,TLSEXT_NAMETYPE_host_name, cast(void*)host);
    }
    char* ERR_reason_error_string(ulong code) const {
        return adapter_ERR_reason_error_string(code);
    }
    ulong ERR_get_error() const {
        return adapter_ERR_get_error();
    }
}
/*
int main() {
    import std.socket;

    auto v = openssl.reportVersion();
    writefln("openSSL v.%s.%s", v.major, v.minor);
    writeln("InitSSL - ok");
    SSL_CTX* ctx = openssl.SSL_CTX_new(openssl.SSLv23_client_method());
    writefln("SSL_CTX_new = %x", ctx);
    int r = openssl.adapter_SSL_CTX_set_default_verify_paths(ctx);
    writefln("SSL_CTX_set_default_verify_paths = %d(%s)", r, r==1?"ok":"fail");
    r = openssl.adapter_SSL_CTX_load_verify_locations(ctx, cast(char*)null, cast(char*)null);
    writefln("SSL_CTX_load_verify_locations - ok");
    openssl.SSL_CTX_set_verify(ctx, 0, null);
    writefln("SSL_CTX_set_verify - ok");
    //r = openssl.SSL_CTX_use_PrivateKey_file(ctx, null, 0);
    //writefln("SSL_CTX_use_PrivateKey_file = %d(%s)", r, r==1?"ok":"fail");
    //r = openssl.SSL_CTX_use_certificate_file(ctx, cast(char*), 0);
    //writefln("SSL_CTX_use_certificate_file = %d(%s)", r, r==1?"ok":"fail");
    SSL* ssl = openssl.SSL_new(ctx);
    writefln("SSL_new = %x", ssl);
    auto s = new Socket(AddressFamily.INET, SocketType.STREAM, ProtocolType.TCP);
    Address[] a = getAddress("datagroup.ua", 443);
    writeln(a[0]);
    s.connect(a[0]);
    r = openssl.SSL_set_fd(ssl, s.handle);
    writefln("SSL_set_fd = %d(%s)", r, r==1?"ok":"fail");
    r = openssl.SSL_connect(ssl);
    writefln("SSL_connect = %d(%s)", r, r==1?"ok":"fail");
    if ( r < 0 ) {
        auto err = openssl.SSL_get_error(ssl, r);
        writefln("code: %d", err);
        writefln("text: %s", openssl.ERR_reason_error_string(err));
    }
    string req = "GET / HTTP/1.0\n\n";
    r = openssl.SSL_write(ssl, cast(void*)req.ptr, cast(int)req.length);
    writefln("SSL_write = %d", r);
    do {
        ubyte[]  resp = new ubyte[](1024);
        r = openssl.SSL_read(ssl, cast(void*)resp.ptr, cast(int)1024);
        writefln("SSL_read = %d", r);
        if ( r > 0 ) {
            writeln(cast(string)resp);
        }
    } while(r > 0);
    openssl.SSL_free(ssl);
    openssl.SSL_CTX_free(ctx);
    s.close();
    return 0;
}
*/
