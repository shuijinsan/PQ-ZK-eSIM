package com.yourcompany.pqzkesim

object ProtocolConstants {
    var DOMAIN_ID = "com.mno.test"

    const val FACE_CAPTURE_TIMEOUT_MS = 10000L
    const val NETWORK_TIMEOUT_MS = 8000L

    // ================================================================
    // ================================================================

    const val N_DIM = 256
    const val K_DIM = 3
    const val M_DIM = 8

    const val POLYVEC_K_BYTES = 3072
    const val POLYVEC_M_BYTES = 8192
    const val POLY_BYTES = 1024

    const val PK_BYTES = 2336
    const val SEED_BYTES = 32
    const val MAC_BYTES = 16

    const val POLYVEC_BYTES = POLYVEC_M_BYTES

    // ================================================================
    // ================================================================
    const val MLKEM_PK_BYTES = 1184
    const val MLKEM_SK_BYTES = 2400
    const val MLKEM_CT_BYTES = 1088
    const val MLKEM_SS_BYTES = 32
    // APDU serialized payload = 32+32+32+3309+3365+16+2336 = 9122 bytes; use 16384 for margin
    const val APDU_MAX_PAYLOAD = 16384

    // ================================================================
    // ================================================================
    const val CERT_BYTES = 3365        // MNO_ID(16) + mno_pk(32) + ca_sig_len(8) + ca_sig(3309)
    const val MNO_ID_BYTES = 16
    const val MLDSA_SIG_BYTES = 3309
}
