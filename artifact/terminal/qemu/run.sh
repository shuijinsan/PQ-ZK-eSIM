#!/bin/bash
# QEMU ARM64 运行包装脚本
# 用法：bash artifact/terminal/qemu/run.sh <binary> [args...]
set -euo pipefail

command -v qemu-aarch64-static >/dev/null 2>&1 || {
  echo "❌ 缺少 qemu-aarch64-static，请安装 qemu-user-static"
  exit 1
}

exec qemu-aarch64-static -L /usr/aarch64-linux-gnu "$@"
