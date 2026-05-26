
# Cross-compiling for ARM64 using Buildroot toolchain
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(TOOLCHAIN_PREFIX /home/ubuntu/pq_zk_project/buildroot-2023.02.6/output/host/bin/aarch64-buildroot-linux-gnu-)

set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}gcc)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}g++)

set(CMAKE_SYSROOT /home/ubuntu/pq_zk_project/buildroot-2023.02.6/output/host/aarch64-buildroot-linux-gnu/sysroot)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(OPENSSL_ROOT_DIR ${CMAKE_SYSROOT}/usr)
set(OPENSSL_INCLUDE_DIR ${CMAKE_SYSROOT}/usr/include)
set(OPENSSL_CRYPTO_LIBRARY ${CMAKE_SYSROOT}/usr/lib/libcrypto.so)
set(OPENSSL_SSL_LIBRARY ${CMAKE_SYSROOT}/usr/lib/libssl.so)
set(liboqs_DIR /home/ubuntu/liboqs/build_aarch64/install)
set(CMAKE_C_FLAGS " -I/home/ubuntu/liboqs/build_aarch64/install/include" CACHE STRING "" FORCE)
set(CMAKE_EXE_LINKER_FLAGS " -L/home/ubuntu/liboqs/build_aarch64/install/lib -loqs -loqs-internal" CACHE STRING "" FORCE)

# Use -O1 for QEMU 8.2 compatibility (-O2 triggers TCG ARM64 emulation bugs)
set(CMAKE_C_FLAGS_RELEASE "-O1 -DNDEBUG" CACHE STRING "" FORCE)
