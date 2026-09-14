package com.yourcompany.pqzkesim

object ProtocolConstants {
    var DOMAIN_ID = "com.mno.test"

    const val HASH_ALGORITHM = "SHA-256"
    const val MAC_ALGORITHM = "HmacSHA256"

    const val FACE_CAPTURE_TIMEOUT_MS = 10000L
    const val NETWORK_TIMEOUT_MS = 8000L

    // ================================================================
    // 精确字节大小常量（严格对齐 C 头文件 pq_zk_esim.h / pqzk_internal.h）
    // ================================================================
    // PQ_ZK_N=256, PQ_ZK_K=5, PQ_ZK_M=8, 每系数4字节(int32_t)

    /** 多项式环维度 */
    const val N_DIM = 256
    /** 承诺维度 (矩阵行数) */
    const val K_DIM = 5
    /** 见证维度 (矩阵列数) */
    const val M_DIM = 8

    /** 承诺向量字节数: K*N*4 = 5*256*4 = 5120 */
    const val POLYVEC_K_BYTES = 5120
    /** 见证/响应向量字节数: M*N*4 = 8*256*4 = 8192 */
    const val POLYVEC_M_BYTES = 8192
    /** 单多项式字节数: N*4 = 256*4 = 1024 */
    const val POLY_BYTES = 1024

    /** 公钥字节数: 32 + K*N*3 = 32 + 5*256*3 = 3872 (24-bit编码) */
    const val PK_BYTES = 3872
    /** 种子/MAC字节数 */
    const val SEED_BYTES = 32
    const val MAC_BYTES = 32

    /** 默认使用最大向量字节数以兼容所有场景 */
    const val POLYVEC_BYTES = POLYVEC_M_BYTES

    // ================================================================
    // ML-KEM (CRYSTALS-Kyber-768) 常量
    // ================================================================
    const val MLKEM_PK_BYTES = 1184
    const val MLKEM_SK_BYTES = 2400
    const val MLKEM_CT_BYTES = 1088
    const val MLKEM_SS_BYTES = 32
    // APDU serialized payload = 32+32+32+3309+3365+16+3872 = 10658 bytes; use 16384 for margin
    const val APDU_MAX_PAYLOAD = 16384

    // ================================================================
    // GSMA 证书常量
    // ================================================================
    const val CERT_BYTES = 3365        // MNO_ID(16) + mno_pk(32) + ca_sig_len(8) + ca_sig(3309)
    const val MNO_ID_BYTES = 16
    const val MLDSA_SIG_BYTES = 3309   // ML-DSA-65 签名长度
}