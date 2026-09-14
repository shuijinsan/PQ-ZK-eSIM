#!/bin/bash
# PQ-ZK-eSIM Artifact — 一键安装依赖并编译
# 目标：reviewer 执行 `bash install.sh` 后即可运行 demo 和 claims
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

echo "== 检查依赖 =="

need() { command -v "$1" >/dev/null 2>&1 || { echo "❌ 缺少依赖: $1 —— $2"; exit 1; }; }

need gcc           "安装 build-essential"
need g++           "安装 build-essential"
need cmake         "安装 cmake（>= 3.22）"
need python3       "安装 python3"
need aarch64-linux-gnu-gcc "安装 gcc-aarch64-linux-gnu（AArch64 交叉编译）"
need qemu-aarch64-static    "安装 qemu-user-static（ARM64 模拟）"

# Valgrind（claim2 Callgrind 需要，>= 3.20）
if ! command -v valgrind >/dev/null 2>&1; then
  echo "⚠️  未找到 valgrind（claim2 需要 >= 3.20，其余 claim 不受影响）"
fi

# Python 绘图包
echo "== 安装 Python 依赖（numpy / pandas / matplotlib）=="
python3 -m pip install --user numpy pandas matplotlib 2>/dev/null || \
  { echo "⚠️  pip 安装失败，可手动执行: python3 -m pip install numpy pandas matplotlib"; }

# OpenSSL / liboqs 由 euicc/build.sh 的静态库或系统 find_package 提供，此处仅提示
echo "== 编译 C 核心（ARM64 + 原生 x86）=="
if [ -f "$ROOT/artifact/terminal/euicc/build.sh" ]; then
  ( cd "$ROOT/artifact/terminal/euicc" && bash build.sh )
else
  echo "❌ 未找到 artifact/terminal/euicc/build.sh"
  exit 1
fi

# 准备各 claim 的 results 目录
echo "== 准备运行目录 =="
mkdir -p claims/claim1_qemu_performance/results \
         claims/claim2_euicc_workload/results \
         claims/claim4_security_estimation/results \
         claims/claim5_desync_dos/results \
         claims/claim6_sparse_noise/results

echo "✅ 安装完成。可运行: bash artifact/demo/run.sh"
echo "   各实验: bash claims/<claim>/run.sh [--quick|--full]"
