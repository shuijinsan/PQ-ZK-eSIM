# SM-DP+ Verifier Guide

The command-line artifact uses the C verifier directly.

The authoritative verification relation is implemented by `PQC_VerifyEngine`
in `artifact/terminal/euicc/src/pq_zk_esim.c` and checks the unmasked response
norms plus `A*z_unmasked - T*c = W (mod q)`.
