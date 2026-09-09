# Cross-compiling for ARM64 (aarch64-linux-gnu toolchain, Ubuntu multiarch)
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(TOOLCHAIN_PREFIX /usr/bin/aarch64-linux-gnu-)
set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}gcc)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}g++)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(OPENSSL_ROOT_DIR /home/ubuntu/openssl_aarch64)
set(OPENSSL_INCLUDE_DIR /home/ubuntu/openssl_aarch64/include)
set(OPENSSL_CRYPTO_LIBRARY /home/ubuntu/openssl_aarch64/lib/libcrypto.a)
set(OPENSSL_SSL_LIBRARY /home/ubuntu/openssl_aarch64/lib/libssl.a)

set(liboqs_DIR /home/ubuntu/liboqs/build_aarch64/install)

set(CMAKE_C_FLAGS " -I/home/ubuntu/liboqs/build_aarch64/install/include -I/home/ubuntu/openssl_aarch64/include" CACHE STRING "" FORCE)
set(CMAKE_EXE_LINKER_FLAGS " -L/home/ubuntu/liboqs/build_aarch64/install/lib -L/home/ubuntu/openssl_aarch64/lib" CACHE STRING "" FORCE)

# Use -O1 for QEMU compatibility
set(CMAKE_C_FLAGS_RELEASE "-O1 -DNDEBUG" CACHE STRING "" FORCE)
