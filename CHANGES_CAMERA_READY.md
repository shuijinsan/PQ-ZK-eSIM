# Camera-Ready Code Changes

This branch aligns the research prototype with the locked camera-ready parameter set without changing the protocol message flow.

## Cryptographic alignment
- Set `N=256`, `q=8380417`, `k=3`, `m=8`, `kappa=35`, `sigma_pub=5000`.
- Use coefficient-wise uniform ternary sampling for the long-term secret and `y_sec`.
- Use the systematic public matrix `A=[Abar|I_3]`, `Abar in R_q^(3x5)`.
- Expand `Abar` with SHAKE-128 and 23-bit rejection sampling.
- Use FIPS-204/ML-DSA-style `SampleInBall` with the protocol-specific weight 35.
- Keep verifier bounds `beta_min=200000`, `beta_max=260000`, `beta_inf=35700`, `beta_L1=7400000`.
- Remove Gaussian pre-clamping; the verifier enforces `beta_inf`.
- Keep MLWE/MSIS estimator inputs fixed to the camera-ready values documented in Claim 2.

## Experiment alignment
- Sparse-noise injection is applied to `y_pub` before `W_pub` and challenge generation, so the linear verification relation remains valid.
- Sparse-noise runs also emit `sparse_noise_norm_breakdown.csv` with individual norm-failure causes.
- The invalid legacy runtime kappa/sigma grid sweep is disabled because the camera-ready sampler parameters are compile-time locked.
- Android JNI and eUICC copies of the cryptographic C core are synchronized.

## Documentation and language
- Project-owned source comments, logs, READMEs, metadata, claim descriptions, and instructions are English.
- Security claims are narrowed to the paper's final scope: no full-view long-term secret-key privacy claim against a malicious LPA; Case-II server privacy is conditional.

## Rerun required
All parameter-dependent timing and attack figures must be regenerated on the final k=3 implementation. Legacy files in `claims/*/expected/` are not camera-ready measurements.
