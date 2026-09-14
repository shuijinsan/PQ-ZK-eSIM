# artifact/terminal/ — 终端 / LPA / eUICC / TEE 环境说明

本目录包含终端侧（LPA）、eUICC prover、TEE 模拟，以及 QEMU/ARM64 运行环境。

## 组件一览

| 组件 | 说明 | 详情 |
|---|---|---|
| `euicc/` | eUICC prover + crypto 核心（C）| euicc/README.md |
| `lpa/` | LPA 前端（Android）| lpa/README.md |
| `tee/` | TEE 模拟（进程内 C 库）| tee/README.md |
| `qemu/` | QEMU ARM64 模拟 | qemu/README.md |
| `arm64/` | AArch64 交叉编译 | arm64/README.md |
| `configs/` | 配置说明 | configs/README.md |
| `scripts/` | 实验/绘图脚本 | — |

## AE 要求的「必须明确」9 项

1. **QEMU 具体版本**：见 qemu/README.md（版本号待 Fresh Clone Test 确认后填写）
2. **ARM64 运行方式**：`qemu-aarch64-static -L /usr/aarch64-linux-gnu <binary>`（封装：qemu/run.sh）
3. **Cortex-A53 模拟方式**：QEMU 模拟 AArch64 指令集（**非真实 Cortex-A53 芯片**）
4. **AArch64 compiler/toolchain**：`gcc-aarch64-linux-gnu` + `euicc/aarch64-toolchain.cmake`
5. **eUICC simulation/model 方式**：C 实现 prover，ARM64 交叉编译后 QEMU 运行（euicc/）
6. **TEE simulation 方式**：进程内 C 库，无独立 TEE 进程（tee/）
7. **LPA 启动方式**：端到端 demo 中由 C 模拟（pqzkesim_app 进程内）；真实前端为 Android（lpa/）
8. **配置文件位置**：编译期常量 `euicc/src/internal/params.h`（configs/README.md）
9. **每个组件启动命令**：见各子目录 README

## 端到端 demo

一条命令跑通全流程（ACCEPT / REJECT）：

```bash
bash artifact/demo/run.sh
```
