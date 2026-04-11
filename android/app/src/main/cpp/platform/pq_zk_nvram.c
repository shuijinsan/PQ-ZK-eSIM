/*
 * pqzk_nvram.c
 * eUICC 模拟器非易失性存储原子读写
 *
 * Linux 原子性保证：tmpfile + fsync + rename
 * POSIX 保证同一文件系统内 rename 是原子的
 *
 * 掉电安全逻辑：
 *   写入临时文件 → fsync → rename 覆盖原文件
 *   若在 rename 前崩溃：原文件保持不变
 *   若在 rename 后崩溃：新状态已生效
 *   严禁先更新计数器再更新密钥（必须同时原子绑定）
 */

#include "pqzk_internal.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#define NVRAM_MAGIC "PQZK"

/* 构造文件路径 */
static void build_path(const char *dir, const char *file, char *out, size_t sz)
{
    snprintf(out, sz, "%s/%s", dir, file);
}

/* ================================================================
 * nvram_read
 * ================================================================ */

int nvram_read(const char *nvram_dir, nvram_state_t *state)
{
    char path[512];
    build_path(nvram_dir, "euicc_state.bin", path, sizeof(path));

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    size_t nr = fread(state, 1, sizeof(nvram_state_t), f);
    fclose(f);

    if (nr != sizeof(nvram_state_t)) return -1;
    if (memcmp(state->magic, NVRAM_MAGIC, 4) != 0) return -1;

    return 0;
}

/* ================================================================
 * nvram_write_atomic
 * tmpfile + fsync + rename
 * ================================================================ */

int nvram_write_atomic(const char *nvram_dir, const nvram_state_t *state)
{
    char path_final[512], path_tmp[512];
    build_path(nvram_dir, "euicc_state.bin",     path_final, sizeof(path_final));
    build_path(nvram_dir, "euicc_state.tmp",     path_tmp,   sizeof(path_tmp));

    /* 1. 写入临时文件 */
    FILE *f = fopen(path_tmp, "wb");
    if (!f) return -1;

    size_t nw = fwrite(state, 1, sizeof(nvram_state_t), f);
    if (nw != sizeof(nvram_state_t)) { fclose(f); return -1; }

    /* 2. fsync 确保数据落盘 */
    if (fflush(f) != 0) { fclose(f); return -1; }
    if (fsync(fileno(f)) != 0) { fclose(f); return -1; }
    fclose(f);

    /* 3. 原子 rename */
    if (rename(path_tmp, path_final) != 0) return -1;

    return 0;
}