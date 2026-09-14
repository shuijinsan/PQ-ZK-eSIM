# 配置文件位置

本 Artifact **没有独立的运行时配置文件**。所有可调参数均为编译期常量：

| 配置 | 位置 | 说明 |
|---|---|---|
| 密码学/协议参数 | `../euicc/src/internal/params.h` | N/K/M、sigma、kappa、beta 等 |
| AArch64 工具链 | `../euicc/aarch64-toolchain.cmake` | 交叉编译工具链路径/标志 |

## 修改方式

修改 `params.h` 后需重新编译（编译方式见 `../arm64/README.md` 或 `../euicc/README.md`）。
