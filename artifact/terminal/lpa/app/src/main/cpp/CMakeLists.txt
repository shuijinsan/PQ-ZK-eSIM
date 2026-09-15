cmake_minimum_required(VERSION 3.22.1)
project("pqzkesim_jni" LANGUAGES C CXX)

# ============================================================
# ============================================================
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17) # OpenCV requires C++14 or newer
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(
    -Wall -Wextra -Wno-unused-parameter
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -O2
    -fomit-frame-pointer
    -fstrict-aliasing
    -funroll-loops
)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-g -fno-omit-frame-pointer)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-DNDEBUG -flto)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -flto")
endif()

add_compile_options(
    -DPQZK_JNI_AGGREGATION     # Enable aggregated JNI bridge
    -DPQZK_TIMING_CONTROL      # Enable authentication timing controls
)

if(ANDROID_ABI STREQUAL "arm64-v8a")
    add_compile_options(-march=armv8-a+crypto -mtune=generic)
endif()

# ============================================================
# ============================================================
set(LIBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libs/${ANDROID_ABI})

set(JNI_LIBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/${ANDROID_ABI})

add_library(liboqs STATIC IMPORTED)
set_target_properties(liboqs PROPERTIES IMPORTED_LOCATION ${LIBS_DIR}/liboqs.a)

add_library(crypto_static STATIC IMPORTED)
set_target_properties(crypto_static PROPERTIES IMPORTED_LOCATION ${LIBS_DIR}/libcrypto.a)

add_library(ssl_static STATIC IMPORTED)
set_target_properties(ssl_static PROPERTIES IMPORTED_LOCATION ${LIBS_DIR}/libssl.a)

add_library(opencv_java4 SHARED IMPORTED)
set_target_properties(opencv_java4 PROPERTIES IMPORTED_LOCATION ${JNI_LIBS_DIR}/libopencv_java4.so)

# ============================================================
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

set(PQZK_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/native-lib.cpp         # JNI aggregation bridge (Phase 0-6)
    ${CMAKE_CURRENT_SOURCE_DIR}/pq_zk_esim.c           # Protocol core
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto/pq-zk-crypto.c  # Cryptographic primitives (SHA3/AES/HMAC/KDF)
    ${CMAKE_CURRENT_SOURCE_DIR}/algebra/pq_zk_poly.c   # Polynomial arithmetic
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/pq_zk_nvram.c # NVRAM persistence
    ${CMAKE_CURRENT_SOURCE_DIR}/tee/pqzk_merkle.c      # Biometric Merkle tree
    ${CMAKE_CURRENT_SOURCE_DIR}/pqzk_mlkem.c           # ML-KEM APDU tunnel
    ${CMAKE_CURRENT_SOURCE_DIR}/pqzk_cert.c            # GSMA certificate-chain model
    ${CMAKE_CURRENT_SOURCE_DIR}/app/mode_switch.c      # Operator switching (Algorithm 3)
)

# ============================================================
# ============================================================
add_library(pqzkesim SHARED ${PQZK_SOURCES})

target_link_libraries(pqzkesim
    liboqs
    ssl_static
    crypto_static
    opencv_java4
    log
    android
    jnigraphics # Bitmap support
    m
    atomic
)

# ============================================================
# ============================================================
message(STATUS "----------------------------------------")
message(STATUS "  Project    : PQ-ZK-eSIM JNI (Phase 0-6 aggregation bridge)")
message(STATUS "  Platform    : Android ${ANDROID_ABI}")
message(STATUS "  Build type    : ${CMAKE_BUILD_TYPE}")
message(STATUS "  C standard  : C${CMAKE_C_STANDARD}")
message(STATUS "  C++ standard : C++${CMAKE_CXX_STANDARD}")
message(STATUS "  Optimization    : O2 (cryptographic timing control)")
message(STATUS "----------------------------------------")
message(STATUS "  Sources  : ${PQZK_SOURCES}")
message(STATUS "----------------------------------------")
