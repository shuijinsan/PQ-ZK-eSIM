#!/bin/bash
# PQ-ZK-eSIM Artifact — 一键安装依赖并编译
# 目标：reviewer 执行 `bash install.sh` 后即可运行 demo 和 claims。
# 特性：set -euo pipefail（失败立即退出）、可重复执行、无硬编码用户路径、
#       自动编译 liboqs / OpenSSL（含 aarch64 交叉编译）。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
EUICC="$ROOT/artifact/terminal/euicc"
AARCH64_DEPS="$EUICC/libs/aarch64"    # aarch64 预编译库目标位置
DEPS_DIR="$ROOT/.deps"                # 源码与临时构建目录（gitignore）
OPENSSL_VERSION="3.0.13"
LIBOQS_VERSION="0.15.0"

log()  { echo "== $* =="; }
fail() { echo "❌ $*"; exit 1; }

cd "$ROOT"

# ------------------------------------------------------------------
# 1. 系统依赖
# ------------------------------------------------------------------
log "检查并安装系统依赖"
command -v sudo >/dev/null 2>&1 || fail "缺少 sudo，无法安装系统包"

PKGS=""
command -v gcc                    >/dev/null 2>&1 || PKGS="$PKGS build-essential"
command -v cmake                  >/dev/null 2>&1 || PKGS="$PKGS cmake"
command -v git                    >/dev/null 2>&1 || PKGS="$PKGS git"
command -v python3                >/dev/null 2>&1 || PKGS="$PKGS python3"
command -v pip3                   >/dev/null 2>&1 || PKGS="$PKGS python3-pip"
command -v aarch64-linux-gnu-gcc  >/dev/null 2>&1 || PKGS="$PKGS gcc-aarch64-linux-gnu"
command -v qemu-aarch64-static    >/dev/null 2>&1 || PKGS="$PKGS qemu-user-static"
command -v wget                   >/dev/null 2>&1 || PKGS="$PKGS wget"
[ -d /usr/include/openssl ]                       || PKGS="$PKGS libssl-dev"
if [ -n "$PKGS" ]; then
  log "安装系统包:$PKGS"
  sudo apt-get update
  sudo apt-get install -y $PKGS
fi

# ------------------------------------------------------------------
# 2. Python 依赖
# ------------------------------------------------------------------
log "安装 Python 依赖（numpy / pandas / matplotlib）"
python3 -m pip install --user numpy pandas matplotlib

# ------------------------------------------------------------------
# 3. OpenSSL（aarch64 静态库）
# ------------------------------------------------------------------
OPENSSL_PREFIX="$AARCH64_DEPS/openssl"
if [ -f "$OPENSSL_PREFIX/lib/libcrypto.a" ]; then
  log "OpenSSL aarch64 已存在，跳过"
else
  log "编译 OpenSSL $OPENSSL_VERSION（aarch64 静态库）"
  mkdir -p "$DEPS_DIR"
  if [ ! -d "$DEPS_DIR/openssl-$OPENSSL_VERSION" ]; then
    ( cd "$DEPS_DIR" \
      && wget "https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz" \
      && tar xf "openssl-$OPENSSL_VERSION.tar.gz" )
  fi
  ( cd "$DEPS_DIR/openssl-$OPENSSL_VERSION" \
    && ./Configure linux-aarch64 --cross-compile-prefix=aarch64-linux-gnu- \
         --prefix="$OPENSSL_PREFIX" no-shared \
    && make -j"$(nproc)" \
    && make install_sw )
fi

# ------------------------------------------------------------------
# 4. liboqs（native + aarch64）
# ------------------------------------------------------------------
LIBOQS_SRC="$DEPS_DIR/liboqs"
if [ ! -d "$LIBOQS_SRC" ]; then
  log "下载 liboqs $LIBOQS_VERSION"
  mkdir -p "$DEPS_DIR"
  git clone --depth 1 --branch "$LIBOQS_VERSION" \
    https://github.com/open-quantum-safe/liboqs.git "$LIBOQS_SRC"
fi

# 4a. native（装到系统，供原生 x86 构建 find_package 使用）
if [ -f /usr/local/lib/liboqs.so ] || [ -f /usr/local/lib/liboqs.a ]; then
  log "liboqs native 已存在，跳过"
else
  log "编译 liboqs（native x86）"
  ( cd "$LIBOQS_SRC" \
    && cmake -S . -B build_native -DCMAKE_BUILD_TYPE=Release \
         -DCMAKE_INSTALL_PREFIX=/usr/local \
    && cmake --build build_native -j"$(nproc)" \
    && sudo cmake --install build_native )
fi

# 4b. aarch64（装到 euicc/libs/aarch64/liboqs）
LIBOQS_AARCH64_PREFIX="$AARCH64_DEPS/liboqs"
if [ -f "$LIBOQS_AARCH64_PREFIX/lib/liboqs.a" ]; then
  log "liboqs aarch64 已存在，跳过"
else
  log "编译 liboqs（aarch64 交叉编译）"
  ( cd "$LIBOQS_SRC" \
    && cmake -S . -B build_aarch64 \
         -DCMAKE_SYSTEM_NAME=Linux \
         -DCMAKE_SYSTEM_PROCESSOR=aarch64 \
         -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
         -DCMAKE_BUILD_TYPE=Release \
         -DCMAKE_INSTALL_PREFIX="$LIBOQS_AARCH64_PREFIX" \
         -DOQS_USE_OPENSSL=ON \
         -DCMAKE_PREFIX_PATH="$OPENSSL_PREFIX" \
    && cmake --build build_aarch64 -j"$(nproc)" \
    && cmake --install build_aarch64 )
fi

# ------------------------------------------------------------------
# 5. 编译 C 核心（ARM64 benchmark + 原生 x86）
# ------------------------------------------------------------------
log "编译 C 核心"
[ -f "$EUICC/build.sh" ] || fail "未找到 $EUICC/build.sh"
( cd "$EUICC" && bash build.sh )

# ------------------------------------------------------------------
# 6. 准备运行目录
# ------------------------------------------------------------------
log "准备运行目录"
mkdir -p claims/claim1_qemu_performance/results \
         claims/claim3_dos_early_reject/results \
         claims/claim4_sliding_window/results \
         claims/claim5_sparse_noise/results

log "安装完成"
echo "  运行 demo : bash artifact/demo/run.sh"
echo "  运行实验 : bash claims/<claim>/run.sh [--quick|--full]"
echo "  校验结果 : bash validate.sh"
