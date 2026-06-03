/*
 * pqzk_merkle.h — PQ-ZK-eSIM biometric Merkle tree
 *
 * Leaf hash: SHA3-256(salt || DID || feature_block)
 * Internal node: SHA3-256(left || right)
 * Padding: pad to power-of-two, duplicate last block
 */

#ifndef PQZK_MERKLE_H
#define PQZK_MERKLE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQZK_MERKLE_MAX_LEAVES  64
#define PQZK_MERKLE_MAX_DEPTH   6
#define PQZK_MERKLE_HASH_BYTES  32

/* Full Merkle tree (stored in TEE) */
typedef struct {
    uint8_t  nodes[PQZK_MERKLE_MAX_DEPTH + 1]
                  [PQZK_MERKLE_MAX_LEAVES]
                  [PQZK_MERKLE_HASH_BYTES];
    uint32_t n_leaves;
    uint32_t depth;
    uint8_t  root[PQZK_MERKLE_HASH_BYTES];
    uint8_t  salt[32];
} merkle_tree_t;

/* Merkle authentication path (M2) */
typedef struct {
    uint8_t  sibling[PQZK_MERKLE_MAX_DEPTH][PQZK_MERKLE_HASH_BYTES];
    uint8_t  is_right_sibling[PQZK_MERKLE_MAX_DEPTH];
    uint32_t depth;
    uint32_t leaf_index;
} merkle_path_t;

int PQC_MerkleTree_Build(
    const uint8_t feature_blocks[][PQZK_MERKLE_HASH_BYTES],
    size_t         n_blocks,
    const uint8_t  salt[32],
    const uint8_t  did[16],
    merkle_tree_t  *tree_out);

int PQC_MerkleTree_GetPath(const merkle_tree_t *tree,
                           uint32_t              M1,
                           merkle_path_t        *path_out);

int PQC_MerkleTree_VerifyPath(
    const uint8_t        leaf_hash[PQZK_MERKLE_HASH_BYTES],
    const merkle_path_t  *path,
    const uint8_t        expected_root[PQZK_MERKLE_HASH_BYTES],
    const uint8_t        salt[32]);

#ifdef __cplusplus
}
#endif

#endif /* PQZK_MERKLE_H */
