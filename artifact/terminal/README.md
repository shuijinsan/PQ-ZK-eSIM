# Terminal-side components
This directory contains the LPA reference frontend, eUICC prover, TEE model, and QEMU/ARM64 execution support.

| Component | Purpose |
|---|---|
| `euicc/` | C prover/verifier and cryptographic core |
| `lpa/` | Android LPA reference application |
| `tee/` | in-process TEE model |
| `qemu/` | QEMU ARM64 execution helper |
| `arm64/` | AArch64 cross-compilation notes |
| `configs/` | compile-time configuration notes |
| `scripts/` | experiment and plotting scripts |

The artifact claims use the C implementation and QEMU ARM64 path. The Android application is reference integration software.
