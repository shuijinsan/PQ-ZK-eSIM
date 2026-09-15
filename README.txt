# PQ-ZK-eSIM Artifact

PQ-ZK-eSIM is a post-quantum, biometric-gated authentication prototype for eSIM provisioning. Biometrics remain inside the TEE, the eUICC stores the lattice witness, and heavy lattice computation is delegated to the LPA/Server.

Core idea: offload the post-quantum authentication workload from the eUICC to the LPA/Server — the eUICC only performs sparse ternary additions (no NTT, no Gaussian sampling), while the heavy lattice arithmetic is carried by the untrusted host (LPA) and the Server. The raw biometric never leaves the TEE.

## 1. Canonical environment
- Ubuntu 22.04 LTS (x86_64)
- 4+ CPU cores, 8 GB RAM, 20 GB free disk
- AArch64 cross-toolchain and QEMU user-mode emulation
- OpenSSL 3.0.13, liboqs 0.15.0
- Python 3 with numpy, pandas, matplotlib

Full platform spec: `infrastructure/environment.txt`; dependency list and versions: `infrastructure/requirements.txt`; third-party libraries and licenses: `infrastructure/THIRD_PARTY.md`.

Install and build:
```bash
bash install.sh
```

`install.sh` is idempotent and completes the whole chain in one pass: install system packages → install Python dependencies → build OpenSSL / liboqs (native + aarch64) → build the C core (native + ARM64) → prepare each claim's `results/` directory.

## 2. Quick start
Run the end-to-end demo:
```bash
bash artifact/demo/run.sh
```
A valid proof should end in ACCEPT; a tampered proof should end in REJECT. Both results are produced by the actual verifier path (not hard-coded text).

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

Note: `--quick` and `--full` are equivalent in the current implementation (parameters are compile-time constants). claim2 depends on the external lattice-estimator (not vendored, fixed commit `6019056`) and is therefore provided as a documented result without a `run.sh`.

### 6.1 Claim directory layout

Each `claims/<claim>/` directory contains:

| File/dir | Purpose |
|---|---|
| `claim.txt` | Which paper Figure/Table the claim reproduces, experiment content, inputs, expected output, runtime, resources, and the **Tolerance** rule |
| `run.sh` | One-shot script that writes CSVs into `results/` (never overwrites `expected/`) |
| `expected/` | Reference results (recorded CSVs + paper figures) |
| `results/` | Actual results produced on this machine (compared against `expected/`) |

### 6.2 Result location

After `run.sh`, actual results land in `claims/<claim>/results/` (e.g. `phase_timing_results.csv`, `dos_results.csv`, `sliding_window_resync_results.csv`, `sparse_noise_attack_results.csv`). Files under `expected/` are left untouched.

## 7. Validation and tolerance

After running the experiments, validate consistency with one command:
```bash
bash validate.sh                          # validate all claims
bash validate.sh claim3_dos_early_reject   # validate a single claim
```

`validate.sh` calls `validate.py`, which compares `results/` against `expected/` column by column, following the **Tolerance** rule in each `claim.txt`:

| Result type | Rule | Rationale |
|---|---|---|
| key (row-identity columns) | exact match (row set + order) | e.g. `rho`, `(window_size, sync_depth)` |
| deterministic results | strict | `success_rate` (1.0 in-window / 0.0 out-of-window), `detection_rate` (ρ≤0.75 → 1.0, ρ=1.0 → 0.0), `Speedup > 1`, operation counts |
| timing results | faster passes; slower ≤ +100% (2×) | `avg_us` / `avg_total_us` latency columns |

Why asymmetric timing tolerance: deterministic results follow from cryptographic/algorithmic properties and must reproduce exactly (e.g. "eUICC has no NTT" is a code-level property, not a timing measurement). Timing results only characterize the workload-split feasibility profile; the paper states QEMU is a *software workload/feasibility profile*, not a real-hardware measurement, and varies per machine. A faster machine (lower latency) is the favorable direction and passes directly; a slower machine is allowed up to 2× the reference (+100%). In addition, claim1's 500 per-sample latency jitter is too large, so only the header and row count are checked, not per-sample µs.

## 8. Protocol overview and security parameters

The protocol splits computation across three parties:

- **TEE** — biometric match + one-time AuthToken issuance;
- **eUICC** — sparse ternary additions only (no NTT, no Gaussian sampling);
- **LPA** (untrusted host) — all heavy lattice arithmetic (blind accelerator).

Server-side four-stage pipelined verification: sliding-window MAC pre-filter → Merkle-path check → unmask → multi-norm lattice verification (relation A·z_unmask − T·c_agg = W).

| Parameter | Value | Meaning |
|---|---|---|
| N | 256 | ring dimension |
| K × M | 3 × 8 | matrix dimensions |
| q | 8,380,417 | modulus (2²³ − 2¹³ + 1) |
| κ | 35 | challenge weight |
| σ_pub | 5,000 | Gaussian flooding width |
| β_∞ | 35,700 | ℓ∞ upper bound |
| β_final / β_min | 260,000 / 200,000 | ℓ₂ upper / lower bound |
| β_L1 | 7,400,000 | L₁ lower bound |

Core properties:
- Post-quantum unforgeability (Module-SIS reduction + low-density decisional SIS assumption)
- eUICC no NTT (only mκN ≈ 7.17×10⁴ ternary additions)
- Biometric non-exposure (contained in TEE; only the Merkle root is public)
- LPA blindness (PRF masking under HKDF-derived keys)
- Server-view simulatability (Gaussian flooding, Rényi-divergence bound)
- DoS resistance (MAC pre-filter early rejection)
- Forward secrecy (per-session KDF key evolution)
- State robustness (sliding-window MAC resynchronization, atomic NVRAM writes)

## 9. Backend (SM-DP+ Verifier)

ACCEPT / REJECT come from real verifier computation, not hard-coded text.

- **Inside the demo (authoritative path)**: `artifact/demo/run.sh` calls `PQC_VerifyEngine` in `artifact/terminal/euicc/src/pq_zk_esim.c` directly (MAC pre-filter → Merkle path → unmask → norm/lattice relation), producing ACCEPT for a valid proof and REJECT for a tampered one — no external service required.
- **Optional FastAPI backend (SM-DP+, networked)**: a separate network backend for integration tests, whose `verify_engine()` mirrors the C-side `PQC_VerifyEngine`. It depends on FastAPI/uvicorn/SQLAlchemy/PyMySQL/redis, MySQL 8.0 + Redis, listens on TCP 8000, and exposes `POST /api/v1/auth/{register,challenge,verify}` (200 valid / 403 invalid). It is **not required** for the paper's core reproducibility claims.

See `SM-DP+_Verifier_Guide.md` for details.

## 10. Repository layout
- `artifact/terminal/euicc/`: C implementation, verifier, lattice arithmetic, TEE/Merkle, ML-KEM/ML-DSA integration, NVRAM model.
- `artifact/terminal/lpa/`: Android/LPA reference application and JNI bridge.
- `artifact/demo/`: end-to-end smoke test.
- `claims/`: reproducibility claims and run scripts.
- `infrastructure/`: environment, dependencies, constraints, access instructions.
- `install.sh`: one-shot installer.
- `validate.sh` / `validate.py`: result consistency validation.
- `metadata.toml`: artifact metadata.
- `license.txt`: license.
- `use.txt`: purpose and limitations.

## 11. Important limitations
- QEMU results are software workload measurements, not real eUICC/TrustZone measurements.
- The 4.2 ms eUICC figure is an analytical dominant-cost projection, not end-to-end wall-clock latency.
- The Gaussian prototype uses Box-Muller continuous-Gaussian sampling followed by rounding; it is an implementation approximation, not a rigorously sampled discrete Gaussian.
- Biometric conditional min-entropy is an assumption and is not empirically established by this artifact.
- The TEE-eUICC binding is a research co-design assumption rather than a standard commodity-eSIM capability.

Network-size note: the paper's communication table is an analytical canonical-packing estimate at 23 bits per ring coefficient. The Android/JNI prototype currently uses 32-bit coefficient containers across JNI for simplicity; cryptographic values and verifier equations are unchanged. Do not use JNI buffer lengths as the paper wire-size measurement.

The parameter-dependent CSV/PNG files under `claims/*/expected/` are legacy reference baselines and must be replaced after the final k=3 rerun before camera-ready archiving.

## 12. Troubleshooting
- Missing dependencies: install item-by-item from `infrastructure/requirements.txt`.

## 13. License
See `license.txt` (Apache 2.0) and `infrastructure/THIRD_PARTY.md`.

## 14. AE contacts
(To be filled in)

See `use.txt`, `CODE_PAPER_AUDIT.md`, `CHANGES_CAMERA_READY.md`, and `infrastructure/constraints.txt` for details.
