# PQ-ZK-eSIM Artifact

PQ-ZK-eSIM is a post-quantum, biometric-gated authentication prototype for eSIM provisioning. Biometrics remain inside the TEE, the eUICC stores the lattice witness, and heavy lattice computation is delegated to the LPA/Server.

## 1. Canonical environment
- Ubuntu 22.04 LTS (x86_64)
- 4+ CPU cores, 8 GB RAM, 20 GB free disk
- AArch64 cross-toolchain and QEMU user-mode emulation
- OpenSSL 3.0.13, liboqs 0.15.0
- Python 3 with numpy, pandas, matplotlib

Install and build:
```bash
bash install.sh
```

## 2. Quick start
Run the end-to-end demo:
```bash
bash artifact/demo/run.sh
```
A valid proof should end in ACCEPT; a tampered proof should end in REJECT. Both results are produced by the actual verifier path.

## 3. Final paper-aligned parameters
- N = 256
- q = 8,380,417
- k = 3, m = 8
- kappa = 35
- sigma_pub = 5000
- secret and y_sec: coefficient-wise uniform ternary U{-1,0,1}
- A = [Abar | I_3], Abar in R_q^(3x5)
- Matrix Abar expansion: SHAKE-128 + 23-bit rejection sampling
- Sparse challenge: FIPS-204/ML-DSA-style SampleInBall with protocol-specific kappa=35
- beta_min = 200,000
- beta_max = 260,000
- beta_inf = 35,700
- beta_L1 = 7,400,000

The eUICC online response costs m*kappa*N = 71,680 ternary-weighted coefficient additions and uses no NTT or Gaussian sampling. Commitment precomputation uses ternary schoolbook convolution with the systematic matrix.

## 4. Security-model scope
The implementation and experiments follow the camera-ready proof scope:
- Malicious LPA case: biometric non-exposure, liveness gating, freshness, and authentication soundness are claimed. No full-view long-term secret-key privacy is claimed against a malicious LPA.
- Honest-but-curious Server case: server-side secret-key privacy additionally assumes an honest LPA, honest Gaussian flooding, non-collusion, and the asymptotic negligible-distance condition stated in the paper.
- The fixed sigma_pub=5000 implementation is reported with finite Renyi-divergence accounting and is not claimed to instantiate the asymptotic negligible-distance UC condition.
- The Fiat-Shamir analysis is in the classical ROM; QROM security is outside the current proof.

## 5. Concrete lattice estimates
The paper uses coefficient embedding for known-attack estimation only.
- MLWE: n=1280, samples=768, q=8380417, Xs=Xe=uniform ternary.
- MSIS: n=768, m=2304, Euclidean norm bound beta=520012, norm=2.
- lattice-estimator commit: 6019056.
- Reported lowest quantum costs: MLWE 162.9 bits, MSIS 155.6 bits.
These are known-attack estimates for the underlying lattice instances, not concrete bit security for the non-tight UC reduction.

## 6. Claims
| Claim | Paper location | Command |
|---|---|---|
| claim1_qemu_performance | QEMU phase timing | `bash claims/claim1_qemu_performance/run.sh --quick` |
| claim2_security_estimation | MLWE/MSIS estimation | documented external lattice-estimator run |
| claim3_dos_early_reject | MAC-before-lattice early reject | `bash claims/claim3_dos_early_reject/run.sh` |
| claim4_sliding_window | sliding-window resynchronization | `bash claims/claim4_sliding_window/run.sh --quick` |
| claim5_sparse_noise | sparse-noise / multi-norm checks | `bash claims/claim5_sparse_noise/run.sh --quick` |

Validate generated results:
```bash
bash validate.sh
```

## 7. Repository layout
- `artifact/terminal/euicc/`: C implementation, verifier, lattice arithmetic, TEE/Merkle, ML-KEM/ML-DSA integration, NVRAM model.
- `artifact/terminal/lpa/`: Android/LPA reference application and JNI bridge.
- `artifact/demo/`: end-to-end smoke test.
- `claims/`: reproducibility claims and run scripts.
- `infrastructure/`: environment, dependencies, constraints, access instructions.

## 8. Important limitations
- QEMU results are software workload measurements, not real eUICC/TrustZone measurements.
- The 4.2 ms eUICC figure is an analytical dominant-cost projection, not end-to-end wall-clock latency.
- The Gaussian prototype uses Box-Muller continuous-Gaussian sampling followed by rounding; it is an implementation approximation, not a rigorously sampled discrete Gaussian.
- Biometric conditional min-entropy is an assumption and is not empirically established by this artifact.
- The TEE-eUICC binding is a research co-design assumption rather than a standard commodity-eSIM capability.

Network-size note: the paper's communication table is an analytical canonical-packing estimate at 23 bits per ring coefficient. The Android/JNI prototype currently uses 32-bit coefficient containers across JNI for simplicity; cryptographic values and verifier equations are unchanged. Do not use JNI buffer lengths as the paper wire-size measurement.

The parameter-dependent CSV/PNG files under `claims/*/expected/` are legacy reference baselines and must be replaced after the final k=3 rerun before camera-ready archiving.

See `use.txt`, `CODE_PAPER_AUDIT.md`, `CHANGES_CAMERA_READY.md`, and `infrastructure/constraints.txt` for details.
