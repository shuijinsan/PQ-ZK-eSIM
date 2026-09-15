#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-$PWD}"
cd "$ROOT"

echo '[1/5] Static source audit'
grep -n '#define PQ_ZK_K' artifact/terminal/euicc/include/pq_zk_esim.h
! grep -R 'sample_binomial_B1' artifact/terminal/euicc/src
! grep -R 'buf\[i\] & 0x03' artifact/terminal/euicc/src

echo '[2/5] Clean native build'
cd artifact/terminal/euicc
rm -rf build-camera-ready
cmake -S . -B build-camera-ready -DCMAKE_BUILD_TYPE=Release
cmake --build build-camera-ready -j"$(nproc)"

echo '[3/5] KAT'
ctest --test-dir build-camera-ready --output-on-failure

echo '[4/5] Short native smoke/performance runs'
cd build-camera-ready
./bench_pqzkesim_comprehensive --only phase
./bench_pqzkesim_comprehensive --only sparse
./bench_pqzkesim_comprehensive --only sliding

echo '[5/5] Done'
echo 'If the native smoke tests pass, run the repository claim scripts/QEMU path used for the paper figures.'
