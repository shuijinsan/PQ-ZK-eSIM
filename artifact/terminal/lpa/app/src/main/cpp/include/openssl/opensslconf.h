/*
 * 手动补齐的 opensslconf.h
 * 专门用于解决 Android NDK 环境下缺少生成文件导致的编译错误
 */

#ifndef OPENSSL_CONFIG_H
#define OPENSSL_CONFIG_H

/* --- 1. 自动适配 64位(arm64-v8a) 与 32位(armeabi-v7a) 架构 --- */
#if defined(__LP64__) || defined(__aarch64__) || defined(__x86_64__)
/* 64位环境配置 */
#   ifndef SIXTY_FOUR_BIT_LONG
#     define SIXTY_FOUR_BIT_LONG
#   endif
#   ifndef BN_ULONG
#     define BN_ULONG unsigned long long
#   endif
#   undef THIRTY_TWO_BIT
#else
/* 32位环境配置 */
#   ifndef THIRTY_TWO_BIT
#     define THIRTY_TWO_BIT
#   endif
#   ifndef BN_ULONG
#     define BN_ULONG unsigned long
#   endif
#   undef SIXTY_FOUR_BIT_LONG
#endif

/* --- 2. 算法与特性屏蔽 (为了在 NDK 环境下顺利链接) --- */
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

/* --- 3. 核心修复：屏蔽所有版本的弃用宏 (解决 bio.h 等报错) --- */
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

/* --- 4. 其他 OpenSSL 必需宏 --- */
#ifndef OPENSSL_THREADS
# define OPENSSL_THREADS
#endif

#endif /* OPENSSL_CONFIG_H */