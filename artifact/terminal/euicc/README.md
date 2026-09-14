# eUICC prover（C 核心）

eUICC 在本 Artifact 中是 **C 实现的 ZK prover**，交叉编译为 ARM64 后由 `qemu-aarch64-static` 执行。**非真实 eUICC 硬件**。

## 协议概览

PQ-ZK-eSIM 把计算分给三方：TEE 做生物特征匹配并签发一次性 AuthToken；eUICC 仅做稀疏三元加法（无 NTT、无高斯采样）；LPA 作为不可信宿主承担重格运算（盲加速器）。服务端通过滑动窗口 MAC 预过滤、Merkle 路径校验、去掩码和带多范数界的格验证完成证明校验。

## 安全参数

| 参数 | 值 | 说明 |
|---|---|---|
| N | 256 | 环维度 |
| K × M | 5 × 8 | 矩阵维度 |
| q | 8,380,417 | 模数 |
| κ | 35 | 挑战权重 |
| σ | 5,000 | 高斯淹没宽度 |
| β_final / β_min / β_L₁ | 260,000 / 200,000 / 7,400,000 | 范数界 |

## 可执行入口（由 CMakeLists.txt 定义）

| 目标 | 源 | 用途 |
|---|---|---|
| `pqzkesim_setup` | app/setup_main.c | 离线注册（生成 NVRAM + registration_data.bin）|
| `pqzkesim_app` | app/main.c | 在线认证 `--auth` / 算子切换 `--switch` |
| `bench_pqzkesim` | benchmarks/bench_pqzkesim.c | 单点 benchmark |
| `bench_pqzkesim_comprehensive` | benchmarks/bench_pqzkesim_comprehensive.c | 综合 benchmark（claims 用）|
| `test_vectors` | test/kat/test_vectors.c | 已知答案测试（KAT）|

## 编译

```bash
# 原生 x86（demo / callgrind 用）
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target pqzkesim_app pqzkesim_setup bench_pqzkesim

# ARM64 交叉编译（QEMU 跑 claims 用）
bash build.sh
```

> 注：`build.sh` 默认只编 benchmark；`pqzkesim_app`/`pqzkesim_setup` 由 `artifact/demo/run.sh` 单独编译。

## 源码结构

```
euicc/
├── src/         算法模块（algebra / crypto / internal / platform / tee + pq_zk_esim.c 等）
├── include/     头文件（pq_zk_esim.h / pqzk_cert.h / pqzk_merkle.h / pqzk_mlkem.h）
├── app/         入口（main.c / setup_main.c / mode_switch.c）
├── benchmarks/  benchmark 源码
├── test/kat/    KAT 测试
├── CMakeLists.txt
└── aarch64-toolchain.cmake
```

## 依赖

OpenSSL 3.0.13 + liboqs 0.15.0（详见顶层 `infrastructure/THIRD_PARTY.md`）。
