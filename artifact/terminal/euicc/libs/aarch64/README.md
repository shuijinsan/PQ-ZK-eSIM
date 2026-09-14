# aarch64 预编译依赖库

本目录存放 ARM64 交叉编译所需的预编译静态库（体积大，不在仓库中，需自行编译后放入）：

```
libs/aarch64/
├── openssl/
│   ├── include/     # OpenSSL 头文件（openssl/*.h）
│   └── lib/         # libcrypto.a, libssl.a
└── liboqs/
    ├── include/     # liboqs 头文件（oqs/*.h）
    └── lib/         # liboqs.a, liboqs-internal.a
```

## 如何获得

1. **liboqs 0.15.0（aarch64）**：下载 liboqs，用 aarch64-linux-gnu-gcc 交叉编译，安装到本目录的 `liboqs/`。
2. **OpenSSL（aarch64 静态库）**：下载 OpenSSL 源码，用 aarch64-linux-gnu-gcc 交叉编译，将 `include/` 和 `lib/libcrypto.a`、`lib/libssl.a` 放入本目录的 `openssl/`。

放置后，`aarch64-toolchain.cmake` 和 `CMakeLists.txt` 会通过相对路径 `${CMAKE_CURRENT_LIST_DIR}/libs/aarch64` 自动找到它们。
