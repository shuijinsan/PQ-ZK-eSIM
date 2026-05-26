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
    message(STATUS "=== Build target: Android ${ANDROID_ABI} ===")
    set(USE_BORING_SSL ON)
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    message(STATUS "=== Build target: Linux ARM64 (cross-compile) ===")
    set(USE_BORING_SSL OFF)
    set(CROSS_ARM64 ON)
else()
    message(STATUS "=== Build target: Linux x86_64 ===")
    set(USE_BORING_SSL OFF)
endif()

# ============================================================
# liboqs dependency
# ARM64: statically linked, paths from toolchain file
# x86_64: find_package
# ============================================================
if(CROSS_ARM64)
    set(liboqs_FOUND TRUE)
    set(liboqs_INCLUDE_DIRS /home/ubuntu/liboqs/build_aarch64/install/include)
    set(liboqs_LIBRARIES /home/ubuntu/liboqs/build_aarch64/install/lib/liboqs.a /home/ubuntu/liboqs/build_aarch64/install/lib/liboqs-internal.a)
else()
    find_package(liboqs REQUIRED)
endif()

# ============================================================
# OpenSSL（Linux）/ BoringSSL（Android NDK 自带）
# ============================================================
if(CROSS_ARM64)
    set(CRYPTO_LIBS /home/ubuntu/pq_zk_project/buildroot-2023.02.6/output/host/aarch64-buildroot-linux-gnu/sysroot/usr/lib/libssl.so /home/ubuntu/pq_zk_project/buildroot-2023.02.6/output/host/aarch64-buildroot-linux-gnu/sysroot/usr/lib/libcrypto.so)
elseif(NOT ANDROID)
    find_package(OpenSSL REQUIRED)
    set(CRYPTO_LIBS OpenSSL::SSL OpenSSL::Crypto)
else()
    # Android NDK r26d 自带 libssl 和 libcrypto（BoringSSL）
    set(CRYPTO_LIBS ssl crypto)
endif()

# ============================================================
# 源文件列表
#
# 新增：src/tee/pqzk_merkle.c（阶段三 Merkle 树，v4.0）
# ============================================================
set(PQZK_SOURCES
    src/pq_zk_esim.c
    src/crypto/pq-zk-crypto.c
    src/algebra/pq_zk_poly.c
    src/platform/pq_zk_nvram.c
    src/tee/pqzk_merkle.c          # 阶段三：生物特征 Merkle 树
    src/pqzk_mlkem.c               # 运营商切换：ML-KEM APDU 隧道
    src/pqzk_cert.c                # 运营商切换：GSMA 证书链模拟
)

# ============================================================
# 头文件搜索路径
# ============================================================
set(PQZK_INCLUDES
    ${CMAKE_CURRENT_SOURCE_DIR}/include          # pq_zk_esim.h / pqzk_merkle.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src              # pq_zk_esim.c 找同目录头文件
    ${CMAKE_CURRENT_SOURCE_DIR}/src/internal     # pqzk_internal.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/tee          # pqzk_mlkem.h / pqzk_cert.h
)

# ============================================================
# 公共链接库（消除重复，统一在此定义）
# ============================================================
if(CROSS_ARM64)
    set(PQZK_LINK_LIBS ${CRYPTO_LIBS} /home/ubuntu/liboqs/build_aarch64/install/lib/liboqs.a /home/ubuntu/liboqs/build_aarch64/install/lib/liboqs-internal.a m)
else()
    set(PQZK_LINK_LIBS ${CRYPTO_LIBS} OQS::oqs m)
endif()

# ============================================================
# 目标 1：核心共享库（Linux .so / Android .so）
# 供后端 Python ctypes 和 Android JNI 调用
# ============================================================
add_library(pqzkesim SHARED ${PQZK_SOURCES})
target_include_directories(pqzkesim PUBLIC ${PQZK_INCLUDES})
target_link_libraries(pqzkesim PRIVATE ${PQZK_LINK_LIBS})
set_target_properties(pqzkesim PROPERTIES
    OUTPUT_NAME  "pqzkesim"
    VERSION      5.0           # 同步 v5.1
    SOVERSION    5
    C_VISIBILITY_PRESET default   # 导出所有符号，供 Python ctypes 直接加载
)

# ============================================================
# 目标 2：验证专用共享库
# 仅包含服务器端验证引擎，供后端独立加载
# ============================================================
add_library(pqzkesim_verify SHARED ${PQZK_SOURCES})
target_include_directories(pqzkesim_verify PUBLIC ${PQZK_INCLUDES})
target_link_libraries(pqzkesim_verify PRIVATE ${PQZK_LINK_LIBS})
set_target_properties(pqzkesim_verify PROPERTIES
    OUTPUT_NAME "pqzkesim_verify"
    VERSION     5.0
    SOVERSION   5
)

# ============================================================
# 目标 3：KAT 测试可执行文件（仅 Linux）
# 运行已知答案测试，验证跨端序列化一致性
# ============================================================
if(NOT ANDROID)
    add_executable(test_vectors
        test/kat/test_vectors.c
        ${PQZK_SOURCES}
    )
    target_include_directories(test_vectors PRIVATE ${PQZK_INCLUDES})
    target_link_libraries(test_vectors PRIVATE ${PQZK_LINK_LIBS})

# ============================================================
# 目标 4：性能基准测试（仅 Linux）
# 参数网格搜索：κ ∈ [20,39] × σ_pub ∈ [80,150]
# 输出 CSV 供论文 Evaluation 章节使用
# ============================================================
    add_executable(bench_pqzkesim
        experiments/benchmarks/bench_pqzkesim.c
        ${PQZK_SOURCES}
    )
    target_include_directories(bench_pqzkesim PRIVATE ${PQZK_INCLUDES})
    target_link_libraries(bench_pqzkesim PRIVATE ${PQZK_LINK_LIBS})

# ============================================================
# 目标 5：综合实验（仅 Linux）
# 包括：稀疏噪声降级攻击、滑动窗口重同步、运营商切换、NVM擦写次数
# ============================================================
    add_executable(bench_pqzkesim_comprehensive
        experiments/benchmarks/bench_pqzkesim_comprehensive.c
        app/mode_switch.c
        ${PQZK_SOURCES}
    )
    target_include_directories(bench_pqzkesim_comprehensive PRIVATE ${PQZK_INCLUDES})
    target_link_libraries(bench_pqzkesim_comprehensive PRIVATE ${PQZK_LINK_LIBS})

# ============================================================
# 目标 6：对比实验（仅 Linux）
# 包括：抗重放攻击、量子复杂度分析、零知识掩码有效性
# ============================================================
    add_executable(bench_comparison
        experiments/benchmarks/bench_comparison_experiments.c
        ${PQZK_SOURCES}
    )
    target_include_directories(bench_comparison PRIVATE ${PQZK_INCLUDES})
    target_link_libraries(bench_comparison PRIVATE ${PQZK_LINK_LIBS})

# ============================================================
# 目标 7：三项目对比实验（仅 Linux）
# 包括：PQ-ZK-eSIM、lpac、PQKEM-5G 的对比
# ============================================================
    add_executable(bench_triple_comparison
        experiments/benchmarks/bench_triple_comparison.c
        ${PQZK_SOURCES}
    )
    target_include_directories(bench_triple_comparison PRIVATE ${PQZK_INCLUDES})
    target_link_libraries(bench_triple_comparison PRIVATE ${PQZK_LINK_LIBS})

# ============================================================
# 目标 8：完整模拟软件（认证 / 运营商切换）
# 用法：
#   认证：./pqzkesim_app --auth --nvram /tmp/euicc
#   切换：./pqzkesim_app --switch --nvram /tmp/euicc --mno-b-id MNO_B_001
# ============================================================
    add_executable(pqzkesim_app
        app/main.c
        app/mode_switch.c
        ${PQZK_SOURCES}
    )
    target_include_directories(pqzkesim_app PRIVATE ${PQZK_INCLUDES})
    target_link_libraries(pqzkesim_app PRIVATE ${PQZK_LINK_LIBS})

# ============================================================
# 目标 9：离线注册工具
# 用法：
#   ./pqzkesim_setup --nvram /tmp/euicc --face features.bin --mno-id MNO_A_SIM_001
# ============================================================
    add_executable(pqzkesim_setup
        app/setup_main.c
        ${PQZK_SOURCES}
    )
    target_include_directories(pqzkesim_setup PRIVATE ${PQZK_INCLUDES})
    target_link_libraries(pqzkesim_setup PRIVATE ${PQZK_LINK_LIBS})

# ============================================================
# CTest 注册
# cmake --build . && ctest 可一键验证所有 KAT
# ============================================================
    enable_testing()
    add_test(NAME KAT COMMAND test_vectors)
    set_tests_properties(KAT PROPERTIES
        PASS_REGULAR_EXPRESSION "0 失败"
    )
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
    include/pqzk_merkle.h      # v4.0 新增，Merkle 树公开接口
    DESTINATION include
)

# ============================================================
# 构建摘要
# ============================================================
message(STATUS "----------------------------------------")
message(STATUS "  项目    : PQ-ZK-eSIM v5.1")
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