/*
 * pqzk_merkle.c  —  PQ-ZK-eSIM v4.0 生物特征 Merkle 树实现
 *
 * 协议对应：
 *   · 阶段零 §0.1 SetupTEE：
 *       leaves ← Pad(Extract(bio_raw), n')
 *       R_bio  ← MerkleRoot(leaves)
 *   · 阶段三 §3：
 *       M2 ← GetPath(tree, M1)
 *   · 阶段六 §6.1：
 *       R_bio' ← ReconstructRoot(M1, M2)，断言 R_bio' == R_bio
 *
 * 节点哈希计算规则（全文统一）：
 *   · 叶子节点：node = SHA-256(feature_block[i])
 *   · 内部节点：node = SHA-256(left_child || right_child)
 *   · 严格按 left || right 拼接，顺序由叶子索引的奇偶性决定
 *
 * 填充规则（协议 §0.1 Pad 函数）：
 *   · 将特征块数量填充到最近的 2^k
 *   · 不足时复制最后一个特征块（padding = last block repeated）
 *
 * 依赖：
 *   · pqzk_internal.h（pqzk_sha256、pqzk_sha256_iov、pqzk_iov_t）
 *
 * 协议版本：4.0
 */

#include "pqzk_internal.h"
#include "pqzk_merkle.h"


#include <string.h>
#include <stdint.h>

/* ================================================================
 * 内部工具函数
 * ================================================================ */

/*
 * next_power_of_two — 计算大于等于 n 的最小 2 的幂
 *
 * 用于确定填充后的叶子数量。
 * 例：n=5 → 8，n=4 → 4，n=1 → 1
 */
static uint32_t next_power_of_two(uint32_t n)
{
    if (n == 0) return 1;
    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    return n + 1;
}

/*
 * log2_u32 — 计算 2 的幂的对数（即树高）
 *
 * 仅对 n 为 2 的幂时结果有效。
 * 例：n=8 → 3，n=4 → 2，n=1 → 0
 */
static uint32_t log2_u32(uint32_t n)
{
    uint32_t r = 0;
    while (n > 1) { n >>= 1; r++; }
    return r;
}

/*
 * hash_node — 计算内部节点哈希
 *
 * parent = SHA-256(left[32] || right[32])
 * 使用 pqzk_sha256_iov 避免拼接缓冲区分配。
 */
static void hash_node(const uint8_t left[PQZK_MERKLE_HASH_BYTES],
                      const uint8_t right[PQZK_MERKLE_HASH_BYTES],
                      uint8_t       out[PQZK_MERKLE_HASH_BYTES])
{
    pqzk_iov_t iov[] = {
        { left,  PQZK_MERKLE_HASH_BYTES },
        { right, PQZK_MERKLE_HASH_BYTES },
        { NULL, 0 }
    };
    pqzk_sha256_iov(iov, out);
}

/* ================================================================
 * PQC_MerkleTree_Build
 * ================================================================ */

/*
 * 建立生物特征 Merkle 树
 *
 * 流程：
 *   1. 计算填充后叶子数量 n_padded = next_power_of_two(n_blocks)
 *   2. 叶子层：对每个特征块计算 SHA-256，填充部分复制最后一块的哈希
 *   3. 逐层向上计算内部节点，直到根节点
 *   4. 根节点写入 tree_out->root（即 R_bio）
 */
int PQC_MerkleTree_Build(
    const uint8_t feature_blocks[][PQZK_MERKLE_HASH_BYTES],
    size_t         n_blocks,
    const uint8_t  salt[32],
    merkle_tree_t *tree_out)
{
    if (!feature_blocks || n_blocks == 0 || !tree_out) return -1;
    if (n_blocks > PQZK_MERKLE_MAX_LEAVES)             return -2;

    memset(tree_out, 0, sizeof(*tree_out));

    /* 步骤1：计算填充后叶子数量和树高 */
    uint32_t n_padded = next_power_of_two((uint32_t)n_blocks);
    uint32_t depth    = log2_u32(n_padded);

    tree_out->n_leaves = n_padded;
    tree_out->depth    = depth;

    /* 步骤2：计算叶子层哈希
     *
     * 叶子哈希 = SHA-256(feature_block[i])
     * 超出 n_blocks 的部分（填充叶子）复制最后一个真实叶子的哈希，
     * 对应协议 Pad 函数的"复制最后一个块"规则。
     */
    for (uint32_t i = 0; i < n_padded; i++) {
        /* 超出原始块范围时，使用最后一个真实块的数据 */
        const uint8_t *block = (i < (uint32_t)n_blocks)
                               ? feature_blocks[i]
                               : feature_blocks[n_blocks - 1];
        /* 叶子哈希 = SHA256(feature_block || salt) */
        pqzk_iov_t leaf_iov[] = {
            { block, PQZK_MERKLE_HASH_BYTES },
            { salt,  32                     },
            { NULL, 0 }
        };
        pqzk_sha256_iov(leaf_iov, tree_out->nodes[0][i]);
    }

    /* 步骤3：逐层向上计算内部节点
     *
     * 第 level 层的节点数 = n_padded >> level
     * 每个父节点 = SHA-256(左子节点 || 右子节点)
     * 层索引 0 = 叶子层，层索引 depth = 根节点层
     */
    for (uint32_t level = 0; level < depth; level++) {
        uint32_t n_nodes = n_padded >> level;       /* 当前层节点数 */
        uint32_t n_parent = n_nodes >> 1;           /* 父层节点数 */
        for (uint32_t i = 0; i < n_parent; i++) {
            hash_node(tree_out->nodes[level][2 * i],
                      tree_out->nodes[level][2 * i + 1],
                      tree_out->nodes[level + 1][i]);
        }
    }

    /* 步骤4：根节点写入 root（= R_bio） */
    memcpy(tree_out->root,
           tree_out->nodes[depth][0],
           PQZK_MERKLE_HASH_BYTES);
    memcpy(tree_out->salt, salt, 32);

    return 0;
}

/* ================================================================
 * PQC_MerkleTree_GetPath
 * ================================================================ */

/*
 * 按叶子索引 M1 提取验证路径 M2
 *
 * 流程：
 *   从叶子层开始，逐层找到当前节点的兄弟节点：
 *   · 若当前节点索引为偶数，兄弟在右侧（索引 + 1），is_right_sibling = 1
 *   · 若当前节点索引为奇数，兄弟在左侧（索引 - 1），is_right_sibling = 0
 *   每层记录兄弟节点哈希和位置，向上移动（索引 >>= 1）
 *
 * 路径方向约定：
 *   验证时，当 is_right_sibling = 1，当前节点在左，兄弟在右：
 *     parent = SHA-256(current || sibling)
 *   当 is_right_sibling = 0，兄弟在左，当前节点在右：
 *     parent = SHA-256(sibling || current)
 */
int PQC_MerkleTree_GetPath(
    const merkle_tree_t *tree,
    uint32_t              M1,
    merkle_path_t        *path_out)
{
    if (!tree || !path_out)          return -1;
    if (M1 >= tree->n_leaves)        return -2;

    memset(path_out, 0, sizeof(*path_out));
    path_out->depth      = tree->depth;
    path_out->leaf_index = M1;

    uint32_t idx = M1;  /* 当前节点在本层的索引 */

    for (uint32_t level = 0; level < tree->depth; level++) {
        uint32_t sibling_idx;

        if (idx % 2 == 0) {
            /* 当前节点在左，兄弟在右 */
            sibling_idx = idx + 1;
            path_out->is_right_sibling[level] = 1;
        } else {
            /* 当前节点在右，兄弟在左 */
            sibling_idx = idx - 1;
            path_out->is_right_sibling[level] = 0;
        }

        memcpy(path_out->sibling[level],
               tree->nodes[level][sibling_idx],
               PQZK_MERKLE_HASH_BYTES);

        idx >>= 1;  /* 移动到父层索引 */
    }

    return 0;
}

/* ================================================================
 * PQC_MerkleTree_VerifyPath
 * ================================================================ */

/*
 * 用 M1 + M2 逐层重构根哈希，与 R_bio 比对
 *
 * 流程：
 *   current = leaf_hash
 *   for level in 0..depth-1:
 *       if is_right_sibling[level]:
 *           current = SHA-256(current || sibling[level])
 *       else:
 *           current = SHA-256(sibling[level] || current)
 *   断言 current == expected_root
 *
 * 对应协议 §6.1：
 *   R_bio' = ReconstructRoot(M1, M2)
 *   assert R_bio' == R_bio
 *
 * 对应后端 Python：
 *   bool verify_merkle_path(M1, M2, expected_root)
 */
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

        if (path->is_right_sibling[level]) {
            /* 当前在左，兄弟在右：parent = SHA-256(current || sibling) */
            hash_node(current, sib, next);
        } else {
            /* 当前在右，兄弟在左：parent = SHA-256(sibling || current) */
            hash_node(sib, current, next);
        }

        memcpy(current, next, PQZK_MERKLE_HASH_BYTES);
    }

    /* 常数时间比较，防止时序侧信道 */
    uint8_t diff = 0;
    for (int i = 0; i < PQZK_MERKLE_HASH_BYTES; i++)
        diff |= current[i] ^ expected_root[i];

    return (diff == 0) ? 0 : -2;
}