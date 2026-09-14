# QEMU ARM64 模拟

## 工具

- `qemu-aarch64-static`（包名 `qemu-user-static`，用户态模拟）
- 具体 QEMU 版本：**待 Fresh Clone Test 确认后填写**

## 运行方式

```bash
qemu-aarch64-static -L /usr/aarch64-linux-gnu <binary> [args...]
```

封装脚本见 `run.sh`（同目录）。

## 示例

```bash
bash run.sh ../euicc/build/arm64/bench_pqzkesim_comprehensive --only phase
```
