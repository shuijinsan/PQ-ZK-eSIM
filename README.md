# PQ-ZK-eSIM

Post-quantum zero-knowledge identity authentication for eSIM.

## Overview

PQ-ZK-eSIM is a C implementation of a lattice-based zero-knowledge authentication protocol for the eSIM profile provisioning phase. The protocol splits computation across three parties:

- **TEE** — performs biometric matching and issues a one-time AuthToken
- **eUICC** — executes only ternary additions (no NTT, no Gaussian sampling)
- **LPA** (untrusted host) — absorbs all heavy lattice operations as a blind accelerator

The server verifies proofs through a four-stage pipeline: sliding-window MAC pre-filter, Merkle path check, unmasking, and lattice verification with multi-norm bounds.

## Parameters 

| Parameter | Value | Description |
|-----------|-------|-------------|
| N | 256 | Ring degree |
| K × M | 5 × 8 | Matrix dimensions |
| q | 8,380,417 | Modulus |
| κ | 35 | Challenge weight |
| σ | 5,000 | Gaussian flooding width |
| β_final | 260,000 | ℓ₂ upper bound |
| β_min | 200,000 | ℓ₂ lower bound |
| β_L₁ | 7,400,000 | L₁ lower bound |

## Building

Requires CMake ≥ 3.22, C11, OpenSSL ≥ 3.0, liboqs.

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j4
```

ARM64 cross-compilation:

```bash
mkdir build/arm64 && cd build/arm64
cmake ../.. -DCMAKE_TOOLCHAIN_FILE=../../aarch64-toolchain.cmake -DCMAKE_BUILD_TYPE=Release
make -j4 bench_pqzkesim
```

## Running

```bash
# Tests
./test_vectors

# Performance (1000 rounds)
./bench_pqzkesim --perf

# Grid search
./bench_pqzkesim --grid

# DoS prevention
./bench_pqzkesim --dos

# Comprehensive experiments
./bench_pqzkesim_comprehensive
```

Charts:

```bash
cd scripts
python3 unified_visualization.py
python3 Grid_search.py --csv ../build/grid_results.csv
```

## Directory

```
src/           Core protocol (crypto, algebra, Merkle tree, NVRAM, PKI, ML-KEM)
include/       Public headers
app/           Simulation tools (auth, registration, operator switching)
experiments/   Benchmarks
test/          Known-answer tests
scripts/       Visualization
```

## Key Properties

- **Post-quantum unforgeability** — Module-SIS reduction
- **NTT-free eUICC** — only mκN ≈ 7.17×10⁴ ternary additions
- **Biometric non-exposure** — TEE-confined, only Merkle root published
- **LPA obliviousness** — PRF masking under HKDF-derived key
- **Server-view simulatability** — Gaussian flooding with Rényi divergence bound
- **DoS resistance** — 185× early reject via MAC pre-filter
- **Forward secrecy** — per-session KDF key evolution
- **State robustness** — sliding-window MAC resync, atomic NVRAM write

## License

MIT
