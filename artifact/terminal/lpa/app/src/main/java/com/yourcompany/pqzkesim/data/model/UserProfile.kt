package com.yourcompany.pqzkesim.data.model

/**
 * User profile data displayed in ProfileFragment.
 * Persisted via file-based storage (UserRepository) — simple enough
 * that Room migration is overkill for now.
 */
data class UserProfile(
    val nickname: String = "PQ-ZK User",
    val userId: String = "eUICC-0000",
    val registerTime: String = "2025-01-01 00:00:00",
    val deviceCount: Int = 0,
    val securityLevel: String = "标准生物级",
    val avatarIndex: Int = 0,
    val customAvatarPath: String? = null
)
