# SM-DP+ Verifier Guide
The command-line artifact uses the C verifier directly. The Android reference integration can optionally connect to an externally hosted FastAPI demonstration backend. That live backend is not part of Claims 1 through 5 and its implementation is not required for reproducing the paper's evaluated results.

The authoritative verification relation is implemented by `PQC_VerifyEngine` in `artifact/terminal/euicc/src/pq_zk_esim.c` and checks the unmasked response norms plus `A*z_unmasked - T*c = W (mod q)`.

The optional backend requires Python, MySQL 8.0, and Redis. It is not required for the paper's core reproducibility claims.
