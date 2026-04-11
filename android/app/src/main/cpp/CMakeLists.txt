cmake_minimum_required(VERSION 3.22.1)
project("pqzkesim_jni" LANGUAGES C CXX)

# ============================================================
# 1. 编译器设置与安全选项
# ============================================================
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 添加安全编译选项 (源自算法师建议)
add_compile_options(
    -Wall -Wextra -Wno-unused-parameter
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O2)
else()
    add_compile_options(-O0 -g)
endif()

# ============================================================
# 2. 静态库导入路径
# ============================================================
# 指向 app/src/main/cpp/libs/arm64-v8a/
set(LIBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libs/${ANDROID_ABI})

# 导入 liboqs
add_library(liboqs STATIC IMPORTED)
set_target_properties(liboqs PROPERTIES
    IMPORTED_LOCATION ${LIBS_DIR}/liboqs.a)

# 导入 OpenSSL 静态库
add_library(crypto_static STATIC IMPORTED)
set_target_properties(crypto_static PROPERTIES
    IMPORTED_LOCATION ${LIBS_DIR}/libcrypto.a)

add_library(ssl_static STATIC IMPORTED)
set_target_properties(ssl_static PROPERTIES
    IMPORTED_LOCATION ${LIBS_DIR}/libssl.a)

# ============================================================
# 3. 头文件与源文件
# ============================================================
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/algebra
    ${CMAKE_CURRENT_SOURCE_DIR}/internal
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto
    ${CMAKE_CURRENT_SOURCE_DIR}/tee
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# 确保包含了 pq_zk_merkle.c 以解决 PQC_MerkleTree_GetPath 报错
set(PQZK_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/pq_zk_esim.c
        ${CMAKE_CURRENT_SOURCE_DIR}/crypto/pq-zk-crypto.c
        ${CMAKE_CURRENT_SOURCE_DIR}/algebra/pq_zk_poly.c
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/pq_zk_nvram.c
        ${CMAKE_CURRENT_SOURCE_DIR}/tee/pqzk_merkle.c      # 显式指向 tee 目录
)

# ============================================================
# 4. 构建与链接
# ============================================================
# 构建算法核心库
add_library(pqzkesim SHARED ${PQZK_SOURCES})

target_link_libraries(pqzkesim
    PRIVATE
    liboqs
    ssl_static
    crypto_static
    log
    m
    atomic
)

# 构建 JNI 接口库
add_library(native-lib SHARED native-lib.cpp)
target_link_libraries(native-lib
    pqzkesim
    log
)