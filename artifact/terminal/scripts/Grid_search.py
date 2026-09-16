#!/usr/bin/env python3
"""PQ-ZK-eSIM locked-parameter summary.

The camera-ready parameter set is fixed.  This utility intentionally does not
infer lattice security from the challenge space or from a kappa/sigma sweep;
MLWE/MSIS costs are obtained from the external lattice-estimator configuration
documented in claim2_security_estimation.
"""
from math import comb, log2

N = 256
Q = 8_380_417
K = 3
M = 8
KAPPA = 35
SIGMA_PUB = 5000.0
BETA_MIN = 200_000
BETA_MAX = 260_000
BETA_INF = 35_700
BETA_L1 = 7_400_000
GAMMA_EXT = max(2 * BETA_INF, 2)


def main() -> None:
    challenge_bits = KAPPA + log2(comb(N, KAPPA))
    print("PQ-ZK-eSIM camera-ready parameter set")
    print(f"N={N}, q={Q}, k={K}, m={M}, kappa={KAPPA}, sigma_pub={SIGMA_PUB:.0f}")
    print("secret/error distribution: coefficient-wise uniform ternary {-1,0,1}")
    print("public matrix: A=[Abar|I_3], Abar in R_q^(3x5)")
    print(f"response dimension mN={M*N}")
    print(f"challenge-space log2 size={challenge_bits:.2f} bits")
    print(f"acceptance: beta_min={BETA_MIN}, beta_max={BETA_MAX}, "
          f"beta_inf={BETA_INF}, beta_L1={BETA_L1}")
    print(f"HNF-MSIS extraction bound gamma_ext={GAMMA_EXT}")
    print("MLWE/MSIS security estimates are external lattice-estimator results; see claim2.")


if __name__ == "__main__":
    main()
