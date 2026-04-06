cmake_minimum_required(VERSION 3.22)
project(pq_zk_esim VERSION 5.0 LANGUAGES C)

# ============================================================
# 编译器基线
# ============================================================
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 安全编译选项
add_compile_options(
    -Wall -Wextra -Wno-unused-parameter
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
)

# Release 模式优化
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O2)
else()
    add_compile_options(-O0 -g)
endif()

# ============================================================
# 平台检测
# ============================================================
if(ANDROID)
    message(STATUS "=== 构建目标：Android ${ANDROID_ABI} ===")
    # Android 不链接系统 OpenSSL，使用 liboqs 自带或 BoringSSL
    set(USE_BORING_SSL ON)
else()
    message(STATUS "=== 构建目标：Linux x86_64 ===")
    set(USE_BORING_SSL OFF)
endif()

# ============================================================
# liboqs 依赖（仅作为底层数学库）
# ============================================================
find_package(liboqs REQUIRED)

# ============================================================
# OpenSSL（Linux）/ BoringSSL（Android NDK 自带）
# ============================================================
if(NOT ANDROID)
    find_package(OpenSSL REQUIRED)
    set(CRYPTO_LIBS OpenSSL::SSL OpenSSL::Crypto)
else()
    # Android NDK r26d 自带 libssl 和 libcrypto（BoringSSL）
    set(CRYPTO_LIBS ssl crypto)
endif()

# ============================================================
# 源文件
# ============================================================
set(PQZK_SOURCES
    src/pq_zk_esim.c
    src/crypto/pq-zk-crypto.c
    src/algebra/pq_zk_poly.c
    src/platform/pq_zk_nvram.c
    src/tee/pqzk_merkle.c
)

set(PQZK_INCLUDES
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src            # 增加这一行，解决 pq_zk_esim.c 找同目录头文件的问题
    ${CMAKE_CURRENT_SOURCE_DIR}/src/internal   # 增加这一行，专门对付那个 internal 里的头文件
)



# ============================================================
# 目标 1：核心共享库（Linux .so / Android .so）
# ============================================================
add_library(pqzkesim SHARED ${PQZK_SOURCES})
target_include_directories(pqzkesim PUBLIC ${PQZK_INCLUDES})
target_link_libraries(pqzkesim PRIVATE OQS::oqs ${CRYPTO_LIBS} m)


# 导出符号（供后端 Python ctypes 加载）
set_target_properties(pqzkesim PROPERTIES
    OUTPUT_NAME "pqzkesim"
    C_VISIBILITY_PRESET default
    VERSION 4.0
    SOVERSION 4
    C_VISIBILITY_PRESET default   # 导出所有符号，供 Python ctypes 直接加载
)

# ============================================================
# 目标 2：验证专用共享库（供后端直接加载）
# ============================================================
add_library(pqzkesim_verify SHARED ${PQZK_SOURCES})
target_include_directories(pqzkesim_verify PUBLIC ${PQZK_INCLUDES})
target_link_libraries(pqzkesim_verify PRIVATE OQS::oqs ${CRYPTO_LIBS} m)
set_target_properties(pqzkesim_verify PROPERTIES OUTPUT_NAME "pqzkesim_verify"
    VERSION     4.0
    SOVERSION   4)


# ============================================================
# 目标 3：测试可执行文件（仅 Linux）
# ============================================================
if(NOT ANDROID)
    add_executable(test_vectors test/kat/test_vectors.c ${PQZK_SOURCES})
    target_include_directories(test_vectors PRIVATE ${PQZK_INCLUDES})
    target_link_libraries(test_vectors PRIVATE OQS::oqs ${CRYPTO_LIBS} m)
  

     add_executable(bench_pqzkesim experiments/benchmarks/bench_pqzkesim.c ${PQZK_SOURCES})
    target_include_directories(bench_pqzkesim PRIVATE ${PQZK_INCLUDES})
    target_link_libraries(bench_pqzkesim PRIVATE OQS::oqs ${CRYPTO_LIBS} m)

  
    # 注册 CTest
    enable_testing()
    add_test(NAME KAT COMMAND test_vectors)
    set_tests_properties(KAT PROPERTIES PASS_REGULAR_EXPRESSION "0 失败")
endif()

# ============================================================
# 安装规则
# ============================================================
install(TARGETS pqzkesim pqzkesim_verify
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)
install(FILES 
            include/pq_zk_esim.h
            include/pqzk_merkle.h  
            DESTINATION include)

# ============================================================
# 打印构建摘要
# ============================================================
message(STATUS "----------------------------------------")
message(STATUS "  项目    : PQ-ZK-eSIM v3.0")
message(STATUS "  平台    : ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "  类型    : ${CMAKE_BUILD_TYPE}")
message(STATUS "  liboqs  : ${liboqs_FOUND}")
message(STATUS "  OpenSSL : ${OPENSSL_VERSION}")
message(STATUS "----------------------------------------")
message(STATUS "Android 交叉编译命令示例：")
message(STATUS "  cmake -DCMAKE_TOOLCHAIN_FILE=\$NDK/build/cmake/android.toolchain.cmake \\")
message(STATUS "        -DANDROID_ABI=arm64-v8a \\")
message(STATUS "        -DANDROID_PLATFORM=android-28 \\")
message(STATUS "        -DCMAKE_BUILD_TYPE=Release ..")
message(STATUS "----------------------------------------")