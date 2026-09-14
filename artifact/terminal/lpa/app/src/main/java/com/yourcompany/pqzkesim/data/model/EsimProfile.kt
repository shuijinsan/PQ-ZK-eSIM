package com.yourcompany.pqzkesim.data.model

/**
 * eSIM profile entity — represents a downloaded operator profile
 * after successful PQC authentication and GSMA certificate verification.
 */
data class EsimProfile(
    val iccid: String,              // eSIM ICCID (20 digits)
    val mnoId: String,              // operator domain ID (16 bytes hex)
    val mnoName: String,            // human-readable operator name
    val phoneNumber: String,        // assigned MSISDN
    val state: EsimProfileState,    // current profile state
    val activatedAt: String = "",   // activation timestamp
    val pkT: ByteArray = ByteArray(0)  // public key T (PQC key)
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EsimProfile) return false
        return iccid == other.iccid
    }

    override fun hashCode(): Int = iccid.hashCode()
}

enum class EsimProfileState {
    DOWNLOADED,     // Profile received from server
    INSTALLING,     // Writing to eUICC NVRAM
    ACTIVE,         // Profile active and operational
    SUSPENDED,      // Temporarily disabled
    ERROR           // Installation failed
}
