/*
 * pqzk_merkle.h  —  PQ-ZK-eSIM v4.0 生物特征 Merkle 树接口
 *
 * 职责：
 *   · 定义 Merkle 树结构体与验证路径结构体
 *   · 声明建树、取路径、验证路径三个核心接口
 *
 * 协议对应：
 *   · 阶段零 §0.1 SetupTEE：建树，生成静态根 R_bio
 *   · 阶段三 §3：TEE 按 M1 取路径 M2
 *   · 阶段六 §6.1：服务器用 M1+M2 重构根节点验证
 *
 * 树结构约定：
 *   · 叶子层：每个叶子 = SHA-256(feature_block[i])，32 字节
 *   · 叶子数量填充至 2^k（不足时复制最后一个叶子）
 *   · 内部节点：parent = SHA-256(left_child || right_child)
 *   · 根节点即为 R_bio（32 字节，注册时上传服务器）
 *   · M2（验证路径）= 从叶子到根路径上每层的兄弟节点哈希列表
 *     配合一个方向位数组（0=兄弟在右，1=兄弟在左）
 *
 * 最大参数限制：
 *   · 叶子数量上限：PQZK_MERKLE_MAX_LEAVES（64）
 *   · 树高上限：PQZK_MERKLE_MAX_DEPTH（6，对应 2^6=64 叶子）
 *
 * 协议版本：4.0
 */

#ifndef PQZK_MERKLE_H
#define PQZK_MERKLE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * 参数限制
 * ================================================================ */

/* 支持的最大叶子数量（填充后，必须是 2 的幂） */
#define PQZK_MERKLE_MAX_LEAVES  64

/* 最大树高（log2(MAX_LEAVES)） */
#define PQZK_MERKLE_MAX_DEPTH   6

/* 哈希长度，固定 32 字节（SHA-256） */
#define PQZK_MERKLE_HASH_BYTES  32

/* ================================================================
 * 数据结构
 * ================================================================ */

/*
 * merkle_tree_t — 完整 Merkle 树（TEE 本地存储）
 *
 * 存储所有层的节点哈希，按层展开：
 *   nodes[0][0..n_leaves-1]   = 叶子层（已哈希）
 *   nodes[1][0..n_leaves/2-1] = 第一层内部节点
 *   ...
 *   nodes[depth][0]           = 根节点 = R_bio
 *
 * depth    = log2(n_padded_leaves)
 * n_leaves = 填充后的叶子数量（2 的幂）
 */
typedef struct {
    uint8_t  nodes[PQZK_MERKLE_MAX_DEPTH + 1]
                  [PQZK_MERKLE_MAX_LEAVES]
                  [PQZK_MERKLE_HASH_BYTES]; /* 所有层的节点哈希 */
    uint32_t n_leaves;   /* 填充后的叶子总数（2 的幂） */
    uint32_t depth;      /* 树高 = log2(n_leaves) */
    uint8_t  root[PQZK_MERKLE_HASH_BYTES]; /* 根节点 = R_bio，冗余存储方便访问 */
    uint8_t  salt[32];
} merkle_tree_t;

/*
 * merkle_path_t — Merkle 验证路径（对应协议中的 M2）
 *
 * 包含从目标叶子到根路径上每层的兄弟节点哈希，
 * 以及每层兄弟节点相对于当前节点的位置（左/右）。
 *
 * 验证方（服务器）利用 M1（叶子索引）和 M2（路径）
 * 逐层重构，最终得到 R_bio' 与数据库中的 R_bio 比对。
 *
 * sibling[0] = 叶子层的兄弟节点
 * sibling[depth-1] = 根节点下方一层的兄弟节点
 * is_right_sibling[i] = 1 表示第 i 层兄弟在右侧，0 表示在左侧
 */
typedef struct {
    uint8_t  sibling[PQZK_MERKLE_MAX_DEPTH][PQZK_MERKLE_HASH_BYTES]; /* 各层兄弟哈希 */
    uint8_t  is_right_sibling[PQZK_MERKLE_MAX_DEPTH]; /* 兄弟位置：1=右侧，0=左侧 */
    uint32_t depth;      /* 路径长度（= 树高） */
    uint32_t leaf_index; /* 叶子索引 M1，冗余存储供验证方核对 */
} merkle_path_t;

/* ================================================================
 * 接口声明
 * ================================================================ */

/*
 * PQC_MerkleTree_Build — 建立生物特征 Merkle 树（阶段零调用）
 *
 * 输入原始特征块数组，每块32字节（模拟环境中为硬编码数据，
 * 真实环境中由 Android TEE 的 Extract(bio_raw) 提供）。
 * 函数内部自动填充叶子数量到 2^k，计算所有层节点哈希。
 *
 * 参数：
 *   feature_blocks  特征块二维数组，每行 32 字节
 *   n_blocks        原始特征块数量（填充前，至少为 1）
 *   tree_out        输出完整树结构
 *
 * 返回：0 成功，-1 参数错误，-2 叶子数量超过最大限制
 */
int PQC_MerkleTree_Build(
    const uint8_t feature_blocks[][PQZK_MERKLE_HASH_BYTES],
    size_t         n_blocks,
    const uint8_t  salt[32],
    merkle_tree_t  *tree_out
);

/*
 * PQC_MerkleTree_GetPath — 按索引 M1 提取验证路径 M2（阶段三 TEE 调用）
 *
 * TEE 根据服务器下发的生物特征挑战索引 M1，从本地存储的
 * 完整树中提取对应的验证路径，作为 M2 返回给 LPA。
 *
 * 参数：
 *   tree      已建立的完整 Merkle 树
 *   M1        服务器下发的叶子索引（0-based，必须 < tree->n_leaves）
 *   path_out  输出验证路径 M2
 *
 * 返回：0 成功，-1 参数错误，-2 M1 越界
 */
int PQC_MerkleTree_GetPath(
    const merkle_tree_t *tree,
    uint32_t              M1,
    merkle_path_t        *path_out
);

/*
 * PQC_MerkleTree_VerifyPath — 验证路径重构根哈希（阶段六服务器调用）
 *
 * 按照标准 Merkle Tree 验证算法，利用 M1 和 M2 逐层重构根哈希，
 * 与数据库中存储的 R_bio 比对。
 *
 * 对应后端 Python 函数 verify_merkle_path(M1, M2, expected_root)。
 *
 * 参数：
 *   leaf_hash      目标叶子的哈希值（32字节，= SHA-256(feature_block[M1])）
 *   path           验证路径 M2
 *   expected_root  数据库中存储的静态根 R_bio（32字节）
 *
 * 返回：0 验证通过（R_bio' == R_bio），-1 参数错误，-2 验证失败
 */
int PQC_MerkleTree_VerifyPath(
    const uint8_t        leaf_hash[PQZK_MERKLE_HASH_BYTES],
    const merkle_path_t  *path,
    const uint8_t        expected_root[PQZK_MERKLE_HASH_BYTES],
    const uint8_t        salt[32]
);

#ifdef __cplusplus
}
#endif

#endif /* PQZK_MERKLE_H */