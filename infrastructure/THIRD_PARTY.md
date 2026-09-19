# Third-party dependencies

PQ-ZK-eSIM is licensed under the **Apache License 2.0** (see `license.txt` in the
repository root). It links against the following third-party libraries. All
are needed to build the benchmarks used by the claims.

| Dependency  | Version (tested) | License        | Used for                                   |
|-------------|------------------|----------------|--------------------------------------------|
| OpenSSL     | 3.0.13           | Apache-2.0     | AES-256-CTR / AES-256-CMAC, SHA-256        |
| liboqs      | 0.15.0           | MIT            | ML-KEM-768 (Kyber-768), ML-DSA-65          |
| CMake       | >= 3.22          | BSD-3-Clause   | build system                               |
| C compiler  | C11 (gcc/clang)  | n/a            | build                                       |

## Build notes

- **Native x86_64** (default): requires OpenSSL >= 3.0 and liboqs to be
  discoverable via `find_package` (system install or `CMAKE_PREFIX_PATH`).
- **ARM64 cross-compile**: the toolchain file `aarch64-toolchain.cmake` points
  at prebuilt static OpenSSL and liboqs (see the file for paths).

The SHA3-256 / SHAKE-256 primitives are implemented in-repo
(`src/crypto/pq-zk-crypto.c`) and do not depend on OpenSSL.
