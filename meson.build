project('dlang-requests', 'd',
    meson_version: '>=0.46',
    license: 'BSL-1.0',
    version: '0.8.0',
)

project_soversion = '0'

pkgc = import('pkgconfig')

#
# Sources
#
requests_src = [
    'source/requests/pool.d',
    'source/requests/uri.d',
    'source/requests/ssl_adapter.d',
    'source/requests/http.d',
    'source/requests/utils.d',
    'source/requests/ftp.d',
    'source/requests/package.d',
    'source/requests/request.d',
    'source/requests/idna/punycode/codec.d',
    'source/requests/idna/punycode/package.d',
    'source/requests/idna/package.d',
    'source/requests/server/httpd.d',
    'source/requests/server/package.d',
    'source/requests/streams.d',
    'source/requests/base.d'
]

src_dir = include_directories('source/')

#
# Targets
#
pg_module_versions = ['USE_PGSQL', 'Derelict_Static']

dlang_requests_lib = library('dlang-requests',
        [requests_src],
        include_directories: [src_dir],
        install: true,
        version: meson.project_version(),
        soversion: project_soversion,
        d_module_versions: ['std']
)
pkgc.generate(name: 'dlang-requests',
              libraries: dlang_requests_lib,
              subdirs: 'd/requests',
              version: meson.project_version(),
              description: 'D HTTP client library inspired by python-requests.',
              d_module_versions: ['std']
)

test_exe = executable('drequests_test',
    [requests_src,
     'tests/httpbin.d',
     'tests/app.d'],
    include_directories: [src_dir, include_directories('tests/')],
    d_unittest: true,
    d_module_versions: ['std', 'httpbin']
)
test('drequests_test', test_exe)

# to allow others to easily use this as a subproject
dlang_requests_dep = declare_dependency(
    link_with: [dlang_requests_lib],
    include_directories: [src_dir]
)

#
# Install
#
install_subdir('source/requests/', install_dir: 'include/d/requests/')
