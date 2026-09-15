# Configuration
There is no independent runtime configuration file. Protocol/security parameters are compile-time constants in `../euicc/src/internal/params.h`; the AArch64 toolchain configuration is in `../euicc/aarch64-toolchain.cmake`. Rebuild after changing any protocol parameter.
