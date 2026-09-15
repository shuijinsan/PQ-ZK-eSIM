# AArch64 static dependencies
Place cross-compiled static dependencies here:
- `liboqs/include`, `liboqs/lib/liboqs.a`
- `openssl/include`, `openssl/lib/libcrypto.a`, `openssl/lib/libssl.a`

`aarch64-toolchain.cmake` and `CMakeLists.txt` resolve these paths relative to this directory.
