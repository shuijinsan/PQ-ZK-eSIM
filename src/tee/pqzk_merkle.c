/*
 * pqzk_merkle.c — PQ-ZK-eSIM v5.2 biometric Merkle tree
 *
 * Leaf hash: SHA3-256(salt || DID || feature_block[i])
 * Internal node: SHA3-256(left || right)
 * Padding: pad to power-of-two, duplicate last block
 */

#include "pqzk_internal.h"
#include "pqzk_merkle.h"

#include <string.h>
#include <stdint.h>

/* Next power of two (for leaf padding) */
static uint32_t next_power_of_two(uint32_t n)
{
    if (n == 0) return 1;
    n--;
    n |= n >> 1;  n |= n >> 2;
    n |= n >> 4;  n |= n >> 8;
    n |= n >> 16;
    return n + 1;
}

/* log2 of a power of two (tree depth) */
static uint32_t log2_u32(uint32_t n)
{
    uint32_t r = 0;
    while (n > 1) { n >>= 1; r++; }
    return r;
}

/* Internal node hash: parent = SHA3-256(left || right) */
static void hash_node(const uint8_t left[PQZK_MERKLE_HASH_BYTES],
                      const uint8_t right[PQZK_MERKLE_HASH_BYTES],
                      uint8_t       out[PQZK_MERKLE_HASH_BYTES])
{
    pqzk_iov_t iov[] = {
        { left,  PQZK_MERKLE_HASH_BYTES },
        { right, PQZK_MERKLE_HASH_BYTES },
        { NULL, 0 }
    };
    pqzk_sha3_256_iov(iov, out);
}

int PQC_MerkleTree_Build(
    const uint8_t feature_blocks[][PQZK_MERKLE_HASH_BYTES],
    size_t         n_blocks,
    const uint8_t  salt[32],
    const uint8_t  did[16],
    merkle_tree_t *tree_out)
{
    if (!feature_blocks || n_blocks == 0 || !tree_out) return -1;
    if (n_blocks > PQZK_MERKLE_MAX_LEAVES)             return -2;

    memset(tree_out, 0, sizeof(*tree_out));

    uint32_t n_padded = next_power_of_two((uint32_t)n_blocks);
    uint32_t depth    = log2_u32(n_padded);
    tree_out->n_leaves = n_padded;
    tree_out->depth    = depth;

    /* Leaf hashes: SHA3-256(salt || DID || block), duplicate last for padding */
    for (uint32_t i = 0; i < n_padded; i++) {
        const uint8_t *block = (i < (uint32_t)n_blocks)
                               ? feature_blocks[i]
                               : feature_blocks[n_blocks - 1];
        pqzk_iov_t leaf_iov[] = {
            { salt,  32                     },
            { did,   16                     },
            { block, PQZK_MERKLE_HASH_BYTES },
            { NULL, 0 }
        };
        pqzk_sha3_256_iov(leaf_iov, tree_out->nodes[0][i]);
    }

    /* Build internal nodes bottom-up */
    for (uint32_t level = 0; level < depth; level++) {
        uint32_t n_parent = (n_padded >> level) >> 1;
        for (uint32_t i = 0; i < n_parent; i++) {
            hash_node(tree_out->nodes[level][2 * i],
                      tree_out->nodes[level][2 * i + 1],
                      tree_out->nodes[level + 1][i]);
        }
    }

    memcpy(tree_out->root, tree_out->nodes[depth][0], PQZK_MERKLE_HASH_BYTES);
    memcpy(tree_out->salt, salt, 32);
    return 0;
}

int PQC_MerkleTree_GetPath(const merkle_tree_t *tree, uint32_t M1,
                           merkle_path_t *path_out)
{
    if (!tree || !path_out)   return -1;
    if (M1 >= tree->n_leaves) return -2;

    memset(path_out, 0, sizeof(*path_out));
    path_out->depth      = tree->depth;
    path_out->leaf_index = M1;

    uint32_t idx = M1;
    for (uint32_t level = 0; level < tree->depth; level++) {
        uint32_t sibling_idx;
        if (idx % 2 == 0) {
            sibling_idx = idx + 1;
            path_out->is_right_sibling[level] = 1;
        } else {
            sibling_idx = idx - 1;
            path_out->is_right_sibling[level] = 0;
        }
        memcpy(path_out->sibling[level],
               tree->nodes[level][sibling_idx],
               PQZK_MERKLE_HASH_BYTES);
        idx >>= 1;
    }
    return 0;
}

int PQC_MerkleTree_VerifyPath(
    const uint8_t        leaf_hash[PQZK_MERKLE_HASH_BYTES],
    const merkle_path_t *path,
    const uint8_t        expected_root[PQZK_MERKLE_HASH_BYTES],
    const uint8_t        salt[32])
{
    if (!leaf_hash || !path || !expected_root) return -1;
    if (path->depth == 0 || path->depth > PQZK_MERKLE_MAX_DEPTH) return -1;

    uint8_t current[PQZK_MERKLE_HASH_BYTES];
    memcpy(current, leaf_hash, PQZK_MERKLE_HASH_BYTES);

    for (uint32_t level = 0; level < path->depth; level++) {
        const uint8_t *sib = path->sibling[level];
        uint8_t next[PQZK_MERKLE_HASH_BYTES];
        if (path->is_right_sibling[level])
            hash_node(current, sib, next);
        else
            hash_node(sib, current, next);
        memcpy(current, next, PQZK_MERKLE_HASH_BYTES);
    }

    /* Constant-time comparison */
    uint8_t diff = 0;
    for (int i = 0; i < PQZK_MERKLE_HASH_BYTES; i++)
        diff |= current[i] ^ expected_root[i];
    return (diff == 0) ? 0 : -2;
}
