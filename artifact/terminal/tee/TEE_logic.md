# PQ-ZK-eSIM TEE logic (AuthToken / Merkle path / verification)

This document describes the TEE-side logic that gates the eUICC prover. It
covers the biometric Merkle tree, the one-time AuthToken, and their
verification. Source files:

- `src/tee/pqzk_merkle.c` + `include/pqzk_merkle.h` — biometric Merkle tree
- `src/pq_zk_esim.c` — `TEE_GenerateAuthToken` (Phase 3) and the AuthToken
  check inside `PQC_ComputeZ_and_Mask` (Phase 4)
- `src/internal/pqzk_internal.h` — `nvram_state_t` layout

## 1. TEE role and trust boundary

The TEE is a hardware-isolated enclave that holds the long-lived biometric
secrets and gates the eUICC's ZK prover:

- **Full biometric Merkle tree** (`merkle_tree_t`), reconstructed on demand.
- **`k_tee`** — the physically-fused symmetric key shared only with the
  eUICC (`PQ_ZK_TEE_KEY_BYTES = 32`), never leaves the TEE/eUICC boundary.
- **`R_bio`** — the published biometric commitment (the Merkle root), which
  is what gets registered with the operator (Cred_KYC / SM-DP+).

The TEE does **not** run any lattice math. Its only job is: given the session
challenge `c_agg` and a chosen biometric leaf index `M1`, prove the leaf is
in the committed tree (`M2`) and bind the session with a MAC (`AuthToken`).

## 2. Biometric Merkle tree

- Leaf hash: `SHA3-256(salt || DID || feature_block[i])`
- Internal node: `SHA3-256(left || right)`
- Padding: pad `n_blocks` up to the next power of two, duplicating the last
  block for the padding leaves.
- Limits: `PQZK_MERKLE_MAX_LEAVES = 128`, `PQZK_MERKLE_MAX_DEPTH = 7`,
  32-byte hashes.

`PQC_MerkleTree_Build(feature_blocks, n_blocks, salt, did, &tree)` builds the
tree bottom-up and stores `root` (= `R_bio`) and `salt`.

## 3. AuthToken generation — `TEE_GenerateAuthToken`

Signature (`include/pq_zk_esim.h`):

```c
PQ_ZK_ErrorCode TEE_GenerateAuthToken(
    const char *nvram_dir, const poly_t *c_agg,
    const uint8_t R_bio[PQZK_MERKLE_HASH_BYTES],
    const merkle_tree_t *tree, uint32_t M1,
    const uint8_t k_tee[PQ_ZK_TEE_KEY_BYTES],
    uint8_t R_dynamic_out[PQ_ZK_SEED_BYTES],
    merkle_path_t *M2_out,
    uint8_t AuthToken_out[PQ_ZK_MAC_BYTES]);
```

Steps:

1. Read `nvram_state_t`; take `ctr_local` as the session counter.
2. Derive the session-dynamic seed:
   `R_dynamic = SHA3-256(R_bio || le64(ctr_local))`
   This binds the static biometric commitment to the monotonic counter, so
   `R_dynamic` is fresh every session.
3. Extract the Merkle authentication path for leaf `M1`:
   `M2 = PQC_MerkleTree_GetPath(tree, M1)`.
4. Emit the one-time token:
   `AuthToken = AES-CMAC(k_tee, Encode(c_agg) || le64(ctr_local) || R_dynamic)`.

Outputs are `R_dynamic`, `M2`, and `AuthToken` (16-byte MAC,
`PQ_ZK_MAC_BYTES`).

## 4. AuthToken verification — inside `PQC_ComputeZ_and_Mask`

The eUICC recomputes the MAC from its own NVRAM copy of `k_tee`, `ctr_local`
and the received `c_agg`/`R_dynamic`, then compares in constant time:

```c
expected = AES-CMAC(state.k_tee, Encode(c_agg) || le64(ctr) || R_dynamic);
mismatch |= expected[i] ^ AuthToken[i];   /* for all MAC bytes */
```

- **Match** → reset `auth_retry_count`, then validate the challenge weight
  (exactly `PQ_ZK_CHALLENGE_WEIGHT = 35` coefficients in {-1,0,1}).
- **Mismatch** → increment `auth_retry_count` (persisted via
  `nvram_write_atomic`); after 3 consecutive failures return
  `PQ_ZK_ERR_RESYNC_NEEDED` (counter-desync signal) and reset the counter,
  otherwise return `PQ_ZK_ERR_MAC_FAIL`.

## 5. Merkle path verification — `PQC_MerkleTree_VerifyPath`

Given a leaf hash, an authentication path, the expected root and the salt,
recompute the root:

```c
current = leaf_hash;
for level in 0 .. depth-1:
    if path.is_right_sibling[level]: current = H(current || sibling)
    else:                            current = H(sibling || current)
return constant_time_equal(current, expected_root) ? 0 : -2;
```

`is_right_sibling[level]` records whether `sibling[level]` is the right
neighbour of the running node, so the hash input order is correct.

## 6. Key data structures

- `merkle_tree_t`: `nodes[depth+1][128][32]`, `n_leaves`, `depth`,
  `root[32]`, `salt[32]`.
- `merkle_path_t`: `sibling[7][32]`, `is_right_sibling[7]`, `depth`,
  `leaf_index`.
- `nvram_state_t` (relevant TEE fields): `k_tee[32]`, `R_bio[32]`,
  `active_R_bio[32]`, `ctr_local`, `auth_retry_count`, `tree_nodes`,
  `tree_n_leaves`, `tree_depth`, `tree_valid`, `salt[32]`.

## 7. Merkle path serialization (M2 on the wire)

`serialize_merkle_path` (in `src/pq_zk_esim.c`) encodes:

```
le32 leaf_index || for each level: (32-byte sibling || 1-byte is_right_sibling)
```

Max size `PQZK_MERKLE_PATH_SERIAL_MAX = 8 + 7*(32+1)`.

## 8. What is simulated vs. real

The biometric **matching** step (comparing a live probe to
`feature_block[M1]`) is abstracted: `M1` is supplied directly. The
cryptographic machinery that the paper relies on — the Merkle commitment,
the authentication path, and the `k_tee`-MAC AuthToken that gates the prover
— is fully implemented and exercised by the benchmarks.
