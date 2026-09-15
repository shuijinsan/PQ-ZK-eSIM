# SM-DP+ Verifier Guide
The command-line artifact uses the C verifier directly. An optional FastAPI backend is also provided for networked integration tests.

The authoritative verification relation is implemented by `PQC_VerifyEngine` in `artifact/terminal/euicc/src/pq_zk_esim.c` and checks the unmasked response norms plus `A*z_unmasked - T*c = W (mod q)`.

The optional backend requires Python, MySQL 8.0, and Redis. It is not required for the paper's core reproducibility claims.
