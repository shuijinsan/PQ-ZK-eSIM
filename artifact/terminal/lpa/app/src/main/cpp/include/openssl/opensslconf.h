/*
 * Project-supplied opensslconf.h compatibility header
 * Used when generated OpenSSL configuration headers are unavailable in the Android NDK build.
 */

#ifndef OPENSSL_CONFIG_H
#define OPENSSL_CONFIG_H

/* --- 1. Architecture selection for arm64-v8a and armeabi-v7a --- */
#if defined(__LP64__) || defined(__aarch64__) || defined(__x86_64__)
/* 64-bit configuration */
#   ifndef SIXTY_FOUR_BIT_LONG
#     define SIXTY_FOUR_BIT_LONG
#   endif
#   ifndef BN_ULONG
#     define BN_ULONG unsigned long long
#   endif
#   undef THIRTY_TWO_BIT
#else
/* 32-bit configuration */
#   ifndef THIRTY_TWO_BIT
#     define THIRTY_TWO_BIT
#   endif
#   ifndef BN_ULONG
#     define BN_ULONG unsigned long
#   endif
#   undef SIXTY_FOUR_BIT_LONG
#endif

/* --- 2. Algorithm/feature exclusions required by the NDK link configuration --- */
#ifndef OPENSSL_NO_ASM
# define OPENSSL_NO_ASM
#endif
#ifndef OPENSSL_NO_ENGINE
# define OPENSSL_NO_ENGINE
#endif
#ifndef OPENSSL_NO_HW
# define OPENSSL_NO_HW
#endif
#ifndef OPENSSL_NO_OCSP
# define OPENSSL_NO_OCSP
#endif

/* --- 3. Compatibility: disable deprecated APIs that break this NDK build --- */
#ifndef DECLARE_DEPRECATED
# define DECLARE_DEPRECATED(f)    f;
#endif

#ifndef DEPRECATEDIN_3_0
# define DEPRECATEDIN_3_0(f)      f;
#endif

#ifndef DEPRECATEDIN_1_1_0
# define DEPRECATEDIN_1_1_0(f)    f;
#endif

#ifndef DEPRECATEDIN_1_0_2
# define DEPRECATEDIN_1_0_2(f)    f;
#endif

#ifndef DEPRECATEDIN_1_0_0
# define DEPRECATEDIN_1_0_0(f)    f;
#endif

#ifndef DEPRECATEDIN_0_9_8
# define DEPRECATEDIN_0_9_8(f)    f;
#endif

/* --- 4. Additional required OpenSSL macros --- */
#ifndef OPENSSL_THREADS
# define OPENSSL_THREADS
#endif

#endif /* OPENSSL_CONFIG_H */