# Code-to-Paper Consistency Audit

## Locked values
| Item | Camera-ready code |
|---|---|
| Ring | `R_q = Z_q[X]/(X^256+1)`, `q=8380417` |
| Module dimensions | `k=3`, `m=8`, `r=m-k=5` |
| Challenge | weight `kappa=35` |
| Flooding width | `sigma_pub=5000` |
| Secret / `y_sec` | coefficient-wise uniform ternary `{-1,0,1}` |
| Public matrix | `A=[Abar|I_3]`, `Abar` is `3x5` |
| Acceptance bounds | `200000 <= ||z||_2 <= 260000`, `||z||_inf <= 35700`, `||z||_1 >= 7400000` |
| Extraction bound | estimator input `beta_2=520012` |

## Paper-matched implementation details
- `T=Abar*s1+s2` is computed with the systematic matrix.
- The eUICC response path uses sparse-challenge ternary additions and performs no NTT or Gaussian sampling.
- `W_sec` uses ternary schoolbook convolution over the random `Abar` block plus the identity block.
- LPA/Server NTT matvec skips the identity block multiplication.
- Gaussian values are not truncated by the sampler; norm rejection occurs at verification.
- The sparse-noise benchmark perturbs `y_pub` while recomputing the matching commitment.
- Matrix generation uses SHAKE-128 rejection sampling; challenge generation follows the FIPS-204/ML-DSA SampleInBall procedure with `kappa=35`.

## Security-claim scope
The code does not attempt to enforce honest Gaussian sampling by a malicious LPA. This matches the final proof scope: malicious-LPA claims are limited to biometric non-exposure, liveness/freshness gating, and authentication soundness. Server-side secret-key privacy is analyzed only for the separate honest-LPA / honest-but-curious-Server case.

## Known prototype abstractions
1. The Gaussian prototype uses Box-Muller continuous Gaussian sampling followed by rounding. It is not a rigorously implemented discrete-Gaussian sampler. The paper's fixed-parameter privacy discussion is therefore finite/illustrative, not an implementation of the asymptotic negligible-distance theorem.
2. The Android/JNI boundary uses 32-bit coefficient containers. The paper's 23-bit communication figure is an analytical canonical-packing estimate and is not a measured JNI payload size.
3. `K_sym`, `d_seed`, TEE keys, and internal sampler seeds are 32 bytes in the implementation. The paper should describe these implementation keys/seeds as 256-bit values when discussing concrete symmetric brute-force strength.
4. The current proof is classical-ROM; the artifact does not implement or claim a QROM proof.

## Static checks performed on this package
- Project Python files compile.
- Project shell scripts pass `bash -n`.
- Android resource XML parses.
- eUICC C sources, applications, benchmarks, and KATs pass GCC syntax checking with only non-fatal portability/unused warnings.
- Core eUICC and Android JNI cryptographic source copies are byte-identical after synchronization.

Full native linking and QEMU/Android execution still require the repository's declared external toolchain/dependencies and must be run on the experiment machine.
