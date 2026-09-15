# QEMU ARM64 execution
Install `qemu-user-static` and run AArch64 binaries with:
```bash
qemu-aarch64-static -L /usr/aarch64-linux-gnu <binary>
```
Use `run.sh` as the wrapper. Results are emulated ARM64 workload measurements, not real Cortex-A53 hardware measurements.
