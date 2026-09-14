# AArch64 交叉编译

## 工具链

- 交叉编译器：`aarch64-linux-gnu-gcc`（包名 `gcc-aarch64-linux-gnu`）
- 工具链 CMake 文件：`../euicc/aarch64-toolchain.cmake`

## 编译命令

```bash
cmake -S ../euicc -B ../euicc/build/arm64 \
      -DCMAKE_TOOLCHAIN_FILE=../euicc/aarch64-toolchain.cmake \
      -DCMAKE_BUILD_TYPE=Release
cmake --build ../euicc/build/arm64 --target bench_pqzkesim bench_pqzkesim_comprehensive -j$(nproc)
```

## 产物

编译产物在 `../euicc/build/arm64/`，由 `qemu-aarch64-static`（见 `../qemu/`）执行。

## Cortex-A53 说明

本 Artifact 的 ARM64 结果由 QEMU 模拟 AArch64 指令集得到，**非真实 Cortex-A53 芯片**。
（措辞：只能写 "QEMU-emulated ARM64/Cortex-A53 evaluation"，不可写 "real hardware benchmark"）
