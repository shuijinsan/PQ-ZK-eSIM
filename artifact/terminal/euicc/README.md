# eUICC C implementation
The eUICC prover is implemented in C and cross-compiled for ARM64/QEMU. It is not a commercial eUICC implementation.

Final paper-aligned parameters:
- N=256, q=8380417
- k=3, m=8
- kappa=35, sigma_pub=5000
- uniform ternary secret and y_sec
- A=[Abar|I_3], Abar in R_q^(3x5)
- beta_min=200000, beta_max=260000, beta_inf=35700, beta_L1=7400000

The online eUICC response uses m*kappa*N=71,680 ternary-weighted coefficient additions and no NTT or Gaussian sampling. The commitment is precomputable and uses ternary schoolbook convolution with the systematic public matrix.

Build:
```bash
bash build.sh
```
The default build produces ARM64 benchmark binaries used by the claims. The demo builds the setup/authentication executables separately.
