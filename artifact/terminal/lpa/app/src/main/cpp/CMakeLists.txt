cmake_minimum_required(VERSION 3.22.1)
project("pqzkesim_jni" LANGUAGES C CXX)

# ============================================================
# 1. 编译器设置与安全选项
# ============================================================
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17) # OpenCV 需要 C++14 以上
set(CMAKE_C_STANDARD_REQUIRED ON)

# 全局优化：密码学运算必须开启 -O2 以上以控制认证延时
add_compile_options(
    -Wall -Wextra -Wno-unused-parameter
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -O2
    -fomit-frame-pointer
    -fstrict-aliasing
    -funroll-loops
)

# Debug 模式下保留符号表但保持优化
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-g -fno-omit-frame-pointer)
endif()

# Release 模式添加链接时优化
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-DNDEBUG -flto)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -flto")
endif()

# Phase 0-6 聚合桥接层计时控制宏
add_compile_options(
    -DPQZK_JNI_AGGREGATION     # 启用聚合 JNI 桥接
    -DPQZK_TIMING_CONTROL      # 启用认证延时控制
)

# ARM NEON 向量化优化（aarch64 平台自动启用）
if(ANDROID_ABI STREQUAL "arm64-v8a")
    add_compile_options(-march=armv8-a+crypto -mtune=generic)
endif()

# ============================================================
# 2. 库导入路径配置
# ============================================================
# 静态库目录：D:\programa\app\src\main\cpp\libs\arm64-v8a
set(LIBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libs/${ANDROID_ABI})

# 动态库目录 (用于 OpenCV)：app/src/main/jniLibs/arm64-v8a
set(JNI_LIBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/${ANDROID_ABI})

# 2.1 导入算法核心静态库 (liboqs, openssl)
add_library(liboqs STATIC IMPORTED)
set_target_properties(liboqs PROPERTIES IMPORTED_LOCATION ${LIBS_DIR}/liboqs.a)

add_library(crypto_static STATIC IMPORTED)
set_target_properties(crypto_static PROPERTIES IMPORTED_LOCATION ${LIBS_DIR}/libcrypto.a)

add_library(ssl_static STATIC IMPORTED)
set_target_properties(ssl_static PROPERTIES IMPORTED_LOCATION ${LIBS_DIR}/libssl.a)

# 2.2 导入 OpenCV 动态库
add_library(opencv_java4 SHARED IMPORTED)
set_target_properties(opencv_java4 PROPERTIES IMPORTED_LOCATION ${JNI_LIBS_DIR}/libopencv_java4.so)

# ============================================================
# 3. 头文件与源文件
# ============================================================
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/algebra
    ${CMAKE_CURRENT_SOURCE_DIR}/internal
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto
    ${CMAKE_CURRENT_SOURCE_DIR}/tee
    ${CMAKE_CURRENT_SOURCE_DIR}/platform
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../opencv/native/jni/include
)

# 汇总所有源文件（Phase 0-6 聚合 JNI 桥接层）
set(PQZK_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/native-lib.cpp         # JNI 聚合桥接层（Phase 0-6）
    ${CMAKE_CURRENT_SOURCE_DIR}/pq_zk_esim.c           # 协议核心实现
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto/pq-zk-crypto.c  # 密码学原语（SHA3/AES/HMAC/KDF）
    ${CMAKE_CURRENT_SOURCE_DIR}/algebra/pq_zk_poly.c   # 多项式代数运算
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/pq_zk_nvram.c # NVRAM 安全持久化存储
    ${CMAKE_CURRENT_SOURCE_DIR}/tee/pqzk_merkle.c      # 生物特征 Merkle 树
    ${CMAKE_CURRENT_SOURCE_DIR}/pqzk_mlkem.c           # ML-KEM APDU 隧道
    ${CMAKE_CURRENT_SOURCE_DIR}/pqzk_cert.c            # GSMA 证书链模拟
    ${CMAKE_CURRENT_SOURCE_DIR}/app/mode_switch.c      # 算子切换 (Algorithm 3)
)

# ============================================================
# 4. 构建与链接
# ============================================================
# 构建唯一的共享库：pqzkesim
# 这样在 Java 层只需 System.loadLibrary("pqzkesim") 即可
add_library(pqzkesim SHARED ${PQZK_SOURCES})

target_link_libraries(pqzkesim
    # 静态链接
    liboqs
    ssl_static
    crypto_static
    # 动态链接 OpenCV
    opencv_java4
    # 系统库
    log
    android
    jnigraphics # 用于处理 Bitmap
    m
    atomic
)

# ============================================================
# 构建摘要
# ============================================================
message(STATUS "----------------------------------------")
message(STATUS "  项目    : PQ-ZK-eSIM JNI (Phase 0-6 聚合桥接)")
message(STATUS "  平台    : Android ${ANDROID_ABI}")
message(STATUS "  类型    : ${CMAKE_BUILD_TYPE}")
message(STATUS "  C 标准  : C${CMAKE_C_STANDARD}")
message(STATUS "  C++标准 : C++${CMAKE_CXX_STANDARD}")
message(STATUS "  优化    : O2 (密码运算延时控制)")
message(STATUS "----------------------------------------")
message(STATUS "  源文件  : ${PQZK_SOURCES}")
message(STATUS "----------------------------------------")