package com.yourcompany.pqzkesim.data.model

data class OperatorInfo(
    val name: String,
    val domainId: String,
    var status: OperatorStatus = OperatorStatus.UNBOUND
)

enum class OperatorStatus(val displayText: String) {
    UNBOUND("未开卡"),
    BOUND("已绑定")
}

object OperatorConfig {
    val CHINA_MOBILE = OperatorInfo(
        name = "中国移动",
        domainId = "CMCC_PQC_01",
        status = OperatorStatus.UNBOUND
    )

    val CHINA_UNICOM = OperatorInfo(
        name = "中国联通",
        domainId = "CUCC_PQC_02",
        status = OperatorStatus.UNBOUND
    )

    val CHINA_TELECOM = OperatorInfo(
        name = "中国电信",
        domainId = "CTCC_PQC_03",
        status = OperatorStatus.UNBOUND
    )

    val ALL_OPERATORS = listOf(CHINA_MOBILE, CHINA_UNICOM, CHINA_TELECOM)

    fun getOperatorByDomain(domainId: String): OperatorInfo? =
        ALL_OPERATORS.find { it.domainId == domainId }

    fun getOperatorByName(name: String): OperatorInfo? =
        ALL_OPERATORS.find { it.name == name }

    /**
     * Maps legacy short domain IDs (from HomeFragment radio buttons) to canonical domain IDs.
     * Accepts both reverse-DNS style ("com.cmcc.mno") and PQC code style ("CMCC_PQC_01").
     */
    fun resolveDomainId(legacyOrCanonical: String): String = when (legacyOrCanonical) {
        "com.cmcc.mno", "CMCC_PQC_01" -> CHINA_MOBILE.domainId
        "com.cucc.mno", "CUCC_PQC_02" -> CHINA_UNICOM.domainId
        "com.ct.mno",   "CTCC_PQC_03" -> CHINA_TELECOM.domainId
        else -> legacyOrCanonical  // passthrough for unknown/custom domains
    }

    /**
     * Looks up operator by either canonical or legacy domain ID.
     */
    fun getOperatorByAnyDomain(domainId: String): OperatorInfo? =
        ALL_OPERATORS.find { it.domainId == resolveDomainId(domainId) }
}
