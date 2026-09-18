#!/bin/bash
#   positive: valid proof -> ACCEPT
#   regression: a second honest session after key/counter evolution -> ACCEPT
#   negative: tampered proof -> REJECT
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EUICC="$ROOT/artifact/terminal/euicc"
WORK="$ROOT/.demo_work"
NVRAM="$WORK/nvram"
NATIVE="$WORK/build_native"

echo "==============================================="
echo "  PQ-ZK-eSIM end-to-end authentication demo"
echo "==============================================="

echo "[build] Build pqzkesim_setup / pqzkesim_app ..."
cmake -S "$EUICC" -B "$NATIVE" -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "$NATIVE" --target pqzkesim_setup pqzkesim_app -j"$(nproc)" >/dev/null

mkdir -p "$WORK"
cd "$WORK"

echo "[setup] Generate synthetic face features (features.bin)"
python3 - <<'EOF'
n = 4
with open("features.bin", "w") as f:
    f.write(f"{n}\n")
    for i in range(n):
        f.write(("%02x" % (0xa0 + i)) * 32 + "\n")
EOF

echo "[1/4] Offline eUICC registration ..."
rm -rf "$NVRAM"
"$NATIVE/pqzkesim_setup" --nvram "$NVRAM" --face features.bin --mno-id MNO_A_SIM_001

echo
echo "[2/4] Online authentication #1 (valid proof; expect ACCEPT)..."
"$NATIVE/pqzkesim_app" --auth --nvram "$NVRAM" 2>&1 | tee "$WORK/auth_ok1.log" || true
if grep -q "Verify PASS" "$WORK/auth_ok1.log"; then
    echo ">>> Result: first authentication ACCEPT"
else
    echo ">>> Result: first authentication failed (expected ACCEPT)"
    exit 1
fi

echo
echo "[3/4] Online authentication #2 after key/counter evolution (expect ACCEPT)..."
"$NATIVE/pqzkesim_app" --auth --nvram "$NVRAM" 2>&1 | tee "$WORK/auth_ok2.log" || true
if grep -q "Verify PASS" "$WORK/auth_ok2.log"; then
    echo ">>> Result: synchronized subsequent authentication ACCEPT"
else
    echo ">>> Result: subsequent authentication failed (Server epoch/key desync)"
    exit 1
fi

echo
echo "[4/4] Tamper with registration_data.bin (public key pk_t) to create an invalid proof (expect REJECT)..."
cp registration_data.bin "$WORK/registration_data.bin.bak"
printf '\x00' | dd of=registration_data.bin bs=1 seek=32 count=1 conv=notrunc 2>/dev/null

"$NATIVE/pqzkesim_app" --auth --nvram "$NVRAM" 2>&1 | tee "$WORK/auth_bad.log" || true
if grep -q "Verify FAIL" "$WORK/auth_bad.log"; then
    echo ">>> Result: tampered public key REJECT"
else
    echo ">>> Result: invalid proof was not rejected (negative case should REJECT)"
    mv "$WORK/registration_data.bin.bak" registration_data.bin
    exit 1
fi

mv "$WORK/registration_data.bin.bak" registration_data.bin

echo
echo "==============================================="
echo "  Demo Done: ACCEPT / ACCEPT / REJECT"
echo "==============================================="
