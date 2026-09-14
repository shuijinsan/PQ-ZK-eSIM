#!/bin/bash
# PQ-ZK-eSIM 端到端 demo
# 流程：Terminal/LPA → TEE gate → eUICC prover → Backend Server → Verifier
#   正向：合法 proof → ACCEPT
#   负向：篡改 proof → REJECT
# 用法：bash artifact/demo/run.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EUICC="$ROOT/artifact/terminal/euicc"
WORK="$ROOT/.demo_work"
NVRAM="$WORK/nvram"
NATIVE="$WORK/build_native"

echo "==============================================="
echo "  PQ-ZK-eSIM 端到端认证 Demo"
echo "==============================================="

# ---- 1. 编译 demo 可执行（原生 x86）----
echo "[build] 编译 pqzkesim_setup / pqzkesim_app ..."
cmake -S "$EUICC" -B "$NATIVE" -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "$NATIVE" --target pqzkesim_setup pqzkesim_app -j"$(nproc)" >/dev/null

mkdir -p "$WORK"
cd "$WORK"

# ---- 2. 生成模拟人脸特征文件（真实流程由 tools/gen_face_feature.py 生成）----
echo "[setup] 生成模拟人脸特征 features.bin"
python3 - <<'EOF'
n = 4
with open("features.bin", "w") as f:
    f.write(f"{n}\n")
    for i in range(n):
        f.write(("%02x" % (0xa0 + i)) * 32 + "\n")
EOF

# ---- 3. 离线注册（Terminal/LPA → eUICC 初始化 + 生成 registration_data.bin）----
echo "[1/3] 离线注册 eUICC ..."
rm -rf "$NVRAM"
"$NATIVE/pqzkesim_setup" --nvram "$NVRAM" --face features.bin --mno-id MNO_A_SIM_001

# ---- 4. 正向认证：合法 proof → 期望 ACCEPT ----
echo
echo "[2/3] 在线认证（合法 proof，期望 ACCEPT）..."
"$NATIVE/pqzkesim_app" --auth --nvram "$NVRAM" 2>&1 | tee "$WORK/auth_ok.log" || true
if grep -q "Verify PASS" "$WORK/auth_ok.log"; then
    echo ">>> 结果: ACCEPT ✓"
else
    echo ">>> 结果: 认证失败（正向应 ACCEPT）"
    exit 1
fi

# ---- 5. 负向认证：篡改公钥，制造非法 proof → 期望 REJECT ----
echo
echo "[3/3] 篡改 registration_data.bin（公钥 pk_t），制造非法 proof（期望 REJECT）..."
cp registration_data.bin "$WORK/registration_data.bin.bak"
# 翻转 registration_data.bin 第 32 字节（pk_t 中 T 公钥的起始位置，跳过前 32 字节矩阵种子）
printf '\x00' | dd of=registration_data.bin bs=1 seek=32 count=1 conv=notrunc 2>/dev/null

"$NATIVE/pqzkesim_app" --auth --nvram "$NVRAM" 2>&1 | tee "$WORK/auth_bad.log" || true
if grep -q "Verify FAIL" "$WORK/auth_bad.log"; then
    echo ">>> 结果: REJECT ✓"
else
    echo ">>> 结果: 非法 proof 未被拒绝（负向应 REJECT）"
    mv "$WORK/registration_data.bin.bak" registration_data.bin
    exit 1
fi

# ---- 恢复 ----
mv "$WORK/registration_data.bin.bak" registration_data.bin

echo
echo "==============================================="
echo "  Demo 完成：正向 ACCEPT ✓ / 负向 REJECT ✓"
echo "==============================================="
