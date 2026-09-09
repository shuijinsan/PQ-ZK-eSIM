cmake_minimum_required(VERSION 3.22)
project(pq_zk_esim VERSION 5.2 LANGUAGES C)

# Compiler baseline
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Security hardening
add_compile_options(
    -Wall -Wextra -Wno-unused-parameter
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
)

# Optimization
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O2)
else()
    add_compile_options(-O0 -g)
endif()

# Platform detection
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

# liboqs
if(CROSS_ARM64)
    set(liboqs_FOUND TRUE)
    set(liboqs_INCLUDE_DIRS /home/ubuntu/liboqs/build_aarch64/install/include)
    set(liboqs_LIBRARIES /home/ubuntu/liboqs/build_aarch64/install/lib/liboqs.a /home/ubuntu/liboqs/build_aarch64/install/lib/liboqs-internal.a)
else()
    find_package(liboqs REQUIRED)
endif()

# OpenSSL / BoringSSL
if(CROSS_ARM64)
    set(CRYPTO_LIBS /home/ubuntu/openssl_aarch64/lib/libssl.a /home/ubuntu/openssl_aarch64/lib/libcrypto.a dl pthread)
elseif(NOT ANDROID)
    find_package(OpenSSL REQUIRED)
    set(CRYPTO_LIBS OpenSSL::SSL OpenSSL::Crypto)
else()
    set(CRYPTO_LIBS ssl crypto)
endif()

# Sources
set(PQZK_SOURCES
    src/pq_zk_esim.c
    src/crypto/pq-zk-crypto.c
    src/algebra/pq_zk_poly.c
    src/platform/pq_zk_nvram.c
    src/tee/pqzk_merkle.c
    src/pqzk_mlkem.c
    src/pqzk_cert.c
)

# Include paths
set(PQZK_INCLUDES
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/internal
    ${CMAKE_CURRENT_SOURCE_DIR}/src/tee
)

# Link libraries
if(CROSS_ARM64)
    set(PQZK_LINK_LIBS ${CRYPTO_LIBS} /home/ubuntu/liboqs/build_aarch64/install/lib/liboqs.a /home/ubuntu/liboqs/build_aarch64/install/lib/liboqs-internal.a m)
else()
    set(PQZK_LINK_LIBS ${CRYPTO_LIBS} OQS::oqs m)
endif()

# Shared library (core)
add_library(pqzkesim SHARED ${PQZK_SOURCES})
target_include_directories(pqzkesim PUBLIC ${PQZK_INCLUDES})
target_link_libraries(pqzkesim PRIVATE ${PQZK_LINK_LIBS})
set_target_properties(pqzkesim PROPERTIES
    OUTPUT_NAME  "pqzkesim"
    VERSION      5.2
    SOVERSION    5
    C_VISIBILITY_PRESET default
)

# Shared library (verify only)
add_library(pqzkesim_verify SHARED ${PQZK_SOURCES})
target_include_directories(pqzkesim_verify PUBLIC ${PQZK_INCLUDES})
target_link_libraries(pqzkesim_verify PRIVATE ${PQZK_LINK_LIBS})
set_target_properties(pqzkesim_verify PROPERTIES
    OUTPUT_NAME "pqzkesim_verify"
    VERSION     5.2
    SOVERSION   5
)

if(NOT ANDROID)
    # KAT tests
    add_executable(test_vectors
        test/kat/test_vectors.c
        ${PQZK_SOURCES}
    )
    target_include_directories(test_vectors PRIVATE ${PQZK_INCLUDES})
    target_link_libraries(test_vectors PRIVATE ${PQZK_LINK_LIBS})

    # Performance benchmark
    add_executable(bench_pqzkesim
        experiments/benchmarks/bench_pqzkesim.c
        ${PQZK_SOURCES}
    )
    target_include_directories(bench_pqzkesim PRIVATE ${PQZK_INCLUDES})
    target_link_libraries(bench_pqzkesim PRIVATE ${PQZK_LINK_LIBS})

    # Comprehensive experiments
    add_executable(bench_pqzkesim_comprehensive
        experiments/benchmarks/bench_pqzkesim_comprehensive.c
        app/mode_switch.c
        ${PQZK_SOURCES}
    )
    target_include_directories(bench_pqzkesim_comprehensive PRIVATE ${PQZK_INCLUDES})
    target_link_libraries(bench_pqzkesim_comprehensive PRIVATE ${PQZK_LINK_LIBS})

    # Comparison experiments
    add_executable(bench_comparison
        experiments/benchmarks/bench_comparison_experiments.c
        ${PQZK_SOURCES}
    )
    target_include_directories(bench_comparison PRIVATE ${PQZK_INCLUDES})
    target_link_libraries(bench_comparison PRIVATE ${PQZK_LINK_LIBS})

    # Triple comparison
    add_executable(bench_triple_comparison
        experiments/benchmarks/bench_triple_comparison.c
        ${PQZK_SOURCES}
    )
    target_include_directories(bench_triple_comparison PRIVATE ${PQZK_INCLUDES})
    target_link_libraries(bench_triple_comparison PRIVATE ${PQZK_LINK_LIBS})

    # Simulation app (auth / switch)
    add_executable(pqzkesim_app
        app/main.c
        app/mode_switch.c
        ${PQZK_SOURCES}
    )
    target_include_directories(pqzkesim_app PRIVATE ${PQZK_INCLUDES})
    target_link_libraries(pqzkesim_app PRIVATE ${PQZK_LINK_LIBS})

    # Offline setup tool
    add_executable(pqzkesim_setup
        app/setup_main.c
        ${PQZK_SOURCES}
    )
    target_include_directories(pqzkesim_setup PRIVATE ${PQZK_INCLUDES})
    target_link_libraries(pqzkesim_setup PRIVATE ${PQZK_LINK_LIBS})

    # CTest
    enable_testing()
    add_test(NAME KAT COMMAND test_vectors)
    set_tests_properties(KAT PROPERTIES
        PASS_REGULAR_EXPRESSION "0 失败"
    )
endif()

# Install
install(TARGETS pqzkesim pqzkesim_verify
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)
install(FILES
    include/pq_zk_esim.h
    include/pqzk_merkle.h
    DESTINATION include
)

# Build summary
message(STATUS "----------------------------------------")
message(STATUS "  Project : PQ-ZK-eSIM v5.2")
message(STATUS "  Platform: ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "  Build   : ${CMAKE_BUILD_TYPE}")
message(STATUS "  liboqs  : ${liboqs_FOUND}")
message(STATUS "  OpenSSL : ${OPENSSL_VERSION}")
message(STATUS "----------------------------------------")
