/*
 * bench_pqzkesim.c — v4.2
 * 参数网格搜索 + 性能基准测试
 *
 * v4.2 变化（相对 v4.1）：
 *   - 在调用 PQC_VerifyEngine 之前，bench 自行做一次范数预检，
 *     将 PQ_ZK_ERR_NORM_BOUND 拆分为两个子类：
 *       overflow_fail  — inf_norm > beta_final（模 q 上界溢出，论文核心指标）
 *       underflow_fail — l2_sq < beta_min²（L2 下界不足，beta_min 设计决定）
 *   - CSV 新增列：overflow_fail, underflow_fail, overflow_rate, underflow_rate
 *   - params.h 注释修正：预期失败率 ~2%（主要来自 beta_min 下界），非 0.1%
 */
#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <stdint.h>

#include "pq_zk_esim.h"
#include "pqzk_internal.h"
#include "params.h"

static double get_time_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

/* ----------------------------------------------------------------
 * 范数预检（复现 PQC_VerifyEngine 步骤3的逻辑）
 * 在调用 VerifyEngine 之前执行，用于区分上界溢出和下界不足。
 *
 * 返回值：
 *   0  — 通过
 *   1  — inf_norm > beta_final（上界溢出）
 *   2  — l2_sq < beta_min²（L2 下界不足）
 * ---------------------------------------------------------------- */
static int norm_precheck(const poly_vec_t *z_unmasked,
                          const beta_params_t *params)
{
    int32_t inf_norm = 0;
    int64_t l2_sq    = 0;
    for (int i = 0; i < PQ_ZK_K * PQ_ZK_N; i++) {
        int32_t v  = (int32_t)z_unmasked->coeffs[i];
        int32_t av = (v < 0) ? -v : v;
        if (av > inf_norm) inf_norm = av;
        l2_sq += (int64_t)v * v;
    }
    if (inf_norm > (int32_t)params->beta_final) return 1;  /* 上界溢出 */
    if (l2_sq < (int64_t)params->beta_min * params->beta_min) return 2; /* 下界不足 */
    return 0;
}

/*
 * run_one_trial
 * 返回值：PQ_ZK_SUCCESS 或具体错误码。
 * overflow_out / underflow_out：各自加 1 当对应情况发生（可传 NULL）。
 */
static PQ_ZK_ErrorCode run_one_trial(const char *nvram_dir,
                                      const uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES],
                                      const uint8_t k_sym[32],
                                      const uint8_t k_tee[32],
                                      const uint8_t R_bio[32],
                                      const uint8_t eid[16],
                                      const poly_vec_t *sk_s,
                                      beta_params_t *params,
                                      double timings[6],
                                      int *overflow_out,
                                      int *underflow_out)
{
    double t0;

    /* ---- 阶段一 ---- */
    poly_vec_t W_pub, W_sec;
    uint8_t seed_y[32], MAC_W[32];

    t0 = get_time_us();
    PQC_PreCompute(&W_pub, seed_y);
    timings[0] = get_time_us() - t0;

    t0 = get_time_us();
    PQC_eUICC_Commit(nvram_dir, &W_sec, MAC_W);
    timings[1] = get_time_us() - t0;

    poly_vec_t W;
    pqzk_vec_add(&W_sec, &W_pub, &W);

    /* ---- 阶段二 ---- */
    uint8_t c_seed[32];
    pqzk_rand_bytes(c_seed, 32);

    poly_t c_agg;
    t0 = get_time_us();
    PQC_GenChallenge(&W, c_seed, &c_agg);
    timings[2] = get_time_us() - t0;

    /* ---- 阶段三：派生 R_dynamic ---- */
    nvram_state_t st;
    nvram_read(nvram_dir, &st);
    uint8_t ctr_bytes[8];
    write_le64(ctr_bytes, st.ctr_local);

    pqzk_iov_t rdyn_iov[] = { { R_bio, 32 }, { ctr_bytes, 8 }, { NULL, 0 } };
    uint8_t R_dynamic[32];
    pqzk_sha256_iov(rdyn_iov, R_dynamic);

    uint8_t cagg_bytes[PQ_ZK_POLY_BYTES];
    PQC_EncodePoly(&c_agg, cagg_bytes);
    uint8_t hash_M2[32];
    pqzk_rand_bytes(hash_M2, 32);

    pqzk_iov_t auth_iov[] = {
        { cagg_bytes, PQ_ZK_POLY_BYTES },
        { ctr_bytes,  8                },
        { R_dynamic,  32               },
        { hash_M2,    32               },
        { NULL, 0 }
    };
    uint8_t AuthToken[32];
    pqzk_hmac_sha256_iov(k_tee, auth_iov, AuthToken);

    /* ---- 阶段四 ---- */
    poly_vec_t z_sec_masked;
    t0 = get_time_us();
    PQ_ZK_ErrorCode rc = PQC_ComputeZ_and_Mask(
        nvram_dir, &c_agg, c_seed,
        R_dynamic, hash_M2, AuthToken, &z_sec_masked);
    timings[3] = get_time_us() - t0;
    if (rc != PQ_ZK_SUCCESS) return rc;

    /* ---- 阶段五 ---- */
    poly_vec_t y_pub, resp_z;
    PQC_RegenerateYpub(seed_y, &y_pub);
    t0 = get_time_us();
    PQC_LPA_Aggregate(&z_sec_masked, &y_pub, &resp_z);
    timings[4] = get_time_us() - t0;

    /* ---- 阶段六：生成 mask，范数预检，再调 VerifyEngine ---- */
    poly_vec_t M_mask;
    t0 = get_time_us();
    PQC_GenerateMask(k_sym, c_seed, st.ctr_local, R_dynamic, &M_mask);

    /* 范数预检：还原 z_unmasked = Lift((resp_z - M_mask) mod q) */
    poly_vec_t z_minus_mask;
    pqzk_vec_sub(&resp_z, &M_mask, &z_minus_mask);
    poly_vec_t z_unmasked;
    for (int i = 0; i < PQ_ZK_K * PQ_ZK_N; i++) {
        int32_t v = (int32_t)(uint16_t)z_minus_mask.coeffs[i];
        if (v > PQ_ZK_Q_VAL / 2) v -= PQ_ZK_Q_VAL;
        z_unmasked.coeffs[i] = (int16_t)v;
    }
    int norm_result = norm_precheck(&z_unmasked, params);
    if (norm_result == 1 && overflow_out)  (*overflow_out)++;
    if (norm_result == 2 && underflow_out) (*underflow_out)++;

    PQ_ZK_ErrorCode vrc = PQC_VerifyEngine(
        PQZK_MATRIX_A_SEED, pk_t, &W, &resp_z,
        c_seed, R_dynamic, &M_mask, params);
    timings[5] = get_time_us() - t0;

    return vrc;
}

/* ================================================================
 * 网格搜索
 * ================================================================ */
static void run_grid_search(void)
{
    printf("\n=== Parameter Grid Search (v4.2) ===\n");

    FILE *csv = fopen("grid_results.csv", "w");
    if (!csv) { perror("fopen"); return; }

    fprintf(csv,
        "kappa,sigma_pub,beta_final,beta_pub,correctness_ok,"
        "overflow_fail,underflow_fail,mac_fail,other_fail,"
        "fail_count,trials,fail_rate,overflow_rate,underflow_rate,"
        "avg_precompute_us,avg_commit_us,avg_challenge_us,"
        "avg_compute_mask_us,avg_aggregate_us,avg_verify_us,avg_total_us\n");

    const char *nvram_dir = "/tmp/pqzk_bench_nvram";
    system("mkdir -p /tmp/pqzk_bench_nvram");

    uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES];
    poly_vec_t sk_s;
    PQC_GenKeyPair(pk_t, &sk_s);

    uint8_t eid[16] = {0};
    uint8_t k_sym[32], k_tee[32], R_bio[32], salt[32], cred_kyc[64];
    pqzk_rand_bytes(k_sym,    32);
    pqzk_rand_bytes(k_tee,    32);
    pqzk_rand_bytes(R_bio,    32);
    pqzk_rand_bytes(salt,     32);
    pqzk_rand_bytes(cred_kyc, 64);

    int total = 0;
    for (int kappa = PQZK_GRID_KAPPA_MIN;
             kappa <= PQZK_GRID_KAPPA_MAX; kappa++) {
        for (double sigma = PQZK_GRID_SIGMA_MIN;
                    sigma <= PQZK_GRID_SIGMA_MAX + 0.01;
                    sigma += PQZK_GRID_SIGMA_STEP) {

            int beta_pub   = (int)(PQZK_TAU * sigma);
            int beta_final = beta_pub + 1 + kappa * PQ_ZK_ETA_S;
            int ok         = (beta_final < 3329/2) ? 1 : 0;

            beta_params_t params;
            params.beta_final = (uint16_t)(beta_final < 65535 ? beta_final : 65534);
            params.beta_min   = PQZK_BETA_MIN;

            int    overflow_fail  = 0;
            int    underflow_fail = 0;
            int    mac_fail       = 0;
            int    other_fail     = 0;
            double sum_t[6]       = {0};

            for (int trial = 0; trial < PQZK_GRID_TRIALS; trial++) {
                uint64_t init_ctr;
                pqzk_rand_bytes((uint8_t*)&init_ctr, 8);
                PQC_eUICC_Init(nvram_dir, eid, 16, &sk_s,
                               k_sym, 32, init_ctr, k_tee, 32,
                               salt, cred_kyc, 64);

                double t[6] = {0};
                PQ_ZK_ErrorCode rc = run_one_trial(
                    nvram_dir, pk_t, k_sym, k_tee, R_bio, eid,
                    &sk_s, &params, t, &overflow_fail, &underflow_fail);

                if (rc != PQ_ZK_SUCCESS) {
                    switch (rc) {
                        case PQ_ZK_ERR_NORM_BOUND: break; /* 已由预检计数 */
                        case PQ_ZK_ERR_MAC_FAIL:   mac_fail++;   break;
                        default:                   other_fail++; break;
                    }
                }
                for (int i = 0; i < 6; i++) sum_t[i] += t[i];
            }

            int    fail_count     = overflow_fail + underflow_fail
                                    + mac_fail + other_fail;
            double fail_rate      = (double)fail_count     / PQZK_GRID_TRIALS;
            double overflow_rate  = (double)overflow_fail  / PQZK_GRID_TRIALS;
            double underflow_rate = (double)underflow_fail / PQZK_GRID_TRIALS;
            double tot = 0;
            for (int i = 0; i < 6; i++) tot += sum_t[i] / PQZK_GRID_TRIALS;

            fprintf(csv,
                "%d,%.1f,%d,%d,%d,"
                "%d,%d,%d,%d,"
                "%d,%d,%.6f,%.6f,%.6f,"
                "%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f\n",
                kappa, sigma, beta_final, beta_pub, ok,
                overflow_fail, underflow_fail, mac_fail, other_fail,
                fail_count, PQZK_GRID_TRIALS,
                fail_rate, overflow_rate, underflow_rate,
                sum_t[0]/PQZK_GRID_TRIALS, sum_t[1]/PQZK_GRID_TRIALS,
                sum_t[2]/PQZK_GRID_TRIALS, sum_t[3]/PQZK_GRID_TRIALS,
                sum_t[4]/PQZK_GRID_TRIALS, sum_t[5]/PQZK_GRID_TRIALS, tot);

            /* 只打印有 overflow 或是最优点的行 */
            if (overflow_fail > 0 || kappa == PQZK_KAPPA)
                printf("k=%2d s=%5.1f bf=%4d ok=%d  "
                       "ov=%3d un=%3d mac=%3d oth=%3d  "
                       "ov_rate=%.4f\n",
                       kappa, sigma, beta_final, ok,
                       overflow_fail, underflow_fail,
                       mac_fail, other_fail, overflow_rate);
            total++;
        }
    }
    fclose(csv);
    system("rm -rf /tmp/pqzk_bench_nvram");
    printf("Total %d combinations. Results -> grid_results.csv\n", total);
}

/* ================================================================
 * 性能基准
 * ================================================================ */
#define PERF_WARMUP 10
#define PERF_REPEAT 100

static void run_perf_bench(void)
{
    printf("\n=== Performance Benchmark v4.2 (k=%d, s=%.1f, %d runs) ===\n",
           PQZK_KAPPA, PQZK_SIGMA_PUB, PERF_REPEAT);

    const char *nvram_dir = "/tmp/pqzk_perf";
    system("mkdir -p /tmp/pqzk_perf");

    uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES];
    poly_vec_t sk_s;
    PQC_GenKeyPair(pk_t, &sk_s);

    uint8_t eid[16]={0}, k_sym[32], k_tee[32], R_bio[32], salt[32], cred_kyc[64];
    pqzk_rand_bytes(k_sym, 32); pqzk_rand_bytes(k_tee, 32);
    pqzk_rand_bytes(R_bio, 32); pqzk_rand_bytes(salt,  32);
    pqzk_rand_bytes(cred_kyc, 64);

    beta_params_t params = PQZK_DEFAULT_BETA_PARAMS;

    for (int i = 0; i < PERF_WARMUP; i++) {
        uint64_t c; pqzk_rand_bytes((uint8_t*)&c, 8);
        PQC_eUICC_Init(nvram_dir, eid, 16, &sk_s,
                       k_sym, 32, c, k_tee, 32, salt, cred_kyc, 64);
        double t[6];
        run_one_trial(nvram_dir, pk_t, k_sym, k_tee,
                      R_bio, eid, &sk_s, &params, t, NULL, NULL);
    }

    double sum[6]={0}, min_t[6], max_t[6];
    for (int i=0;i<6;i++){min_t[i]=1e9; max_t[i]=0;}
    int ok_cnt=0, ov_cnt=0, un_cnt=0, mac_cnt=0, oth_cnt=0;

    for (int r = 0; r < PERF_REPEAT; r++) {
        uint64_t c; pqzk_rand_bytes((uint8_t*)&c, 8);
        PQC_eUICC_Init(nvram_dir, eid, 16, &sk_s,
                       k_sym, 32, c, k_tee, 32, salt, cred_kyc, 64);
        double t[6];
        PQ_ZK_ErrorCode rc = run_one_trial(
            nvram_dir, pk_t, k_sym, k_tee, R_bio, eid,
            &sk_s, &params, t, &ov_cnt, &un_cnt);
        if (rc == PQ_ZK_SUCCESS)        ok_cnt++;
        else if (rc == PQ_ZK_ERR_MAC_FAIL) mac_cnt++;
        else if (rc != PQ_ZK_ERR_NORM_BOUND) oth_cnt++;
        for (int i=0;i<6;i++){
            sum[i]+=t[i];
            if(t[i]<min_t[i]) min_t[i]=t[i];
            if(t[i]>max_t[i]) max_t[i]=t[i];
        }
    }

    const char *names[] = {
        "PreCompute (LPA)",
        "eUICC_Commit (eUICC)",
        "GenChallenge (LPA)",
        "ComputeZ_and_Mask (eUICC)",
        "LPA_Aggregate",
        "GenerateMask+VerifyEngine (Server)",
    };
    double total_avg = 0;
    double euicc_total = 0, lpa_total = 0, server_total = 0;
    
    // 计算各环境总时间
    euicc_total = sum[1] + sum[3];  // eUICC_Commit + ComputeZ_and_Mask
    lpa_total = sum[0] + sum[2] + sum[4];  // PreCompute + GenChallenge + LPA_Aggregate
    server_total = sum[5];  // GenerateMask+VerifyEngine
    
    printf("\n%-38s %8s %8s %8s\n","Function","avg(us)","min","max");
    printf("%-38s %8s %8s %8s\n","--------","-------","---","---");
    for (int i=0;i<6;i++){
        double avg=sum[i]/PERF_REPEAT;
        total_avg+=avg;
        printf("%-38s %8.1f %8.1f %8.1f\n",names[i],avg,min_t[i],max_t[i]);
    }
    printf("%-38s %8.1f\n","End-to-end total",total_avg);
    
    // 打印环境分离结果
    printf("\n=== Environment Breakdown ===\n");
    printf("eUICC (resource-constrained): %8.1f us\n", euicc_total/PERF_REPEAT);
    printf("LPA (high-power):              %8.1f us\n", lpa_total/PERF_REPEAT);
    printf("Server:                        %8.1f us\n", server_total/PERF_REPEAT);
    
    printf("\nSuccess             : %d/%d = %.1f%%\n",
           ok_cnt,PERF_REPEAT,100.0*ok_cnt/PERF_REPEAT);
    printf("Overflow  (ov_norm) : %d/%d = %.1f%%  <- mod-q overflow\n",
           ov_cnt,PERF_REPEAT,100.0*ov_cnt/PERF_REPEAT);
    printf("Underflow (un_norm) : %d/%d = %.1f%%  <- beta_min design\n",
           un_cnt,PERF_REPEAT,100.0*un_cnt/PERF_REPEAT);
    printf("MAC fail            : %d/%d = %.1f%%\n",
           mac_cnt,PERF_REPEAT,100.0*mac_cnt/PERF_REPEAT);
    printf("Other               : %d/%d = %.1f%%\n",
           oth_cnt,PERF_REPEAT,100.0*oth_cnt/PERF_REPEAT);

    FILE *f=fopen("perf_results.csv","w");
    if(f){
        fprintf(f,"function,avg_us,min_us,max_us\n");
        for(int i=0;i<6;i++)
            fprintf(f,"%s,%.2f,%.2f,%.2f\n",
                    names[i],sum[i]/PERF_REPEAT,min_t[i],max_t[i]);
        fprintf(f,"total,%.2f,,\n",total_avg);
        fprintf(f,"eUICC_total,%.2f,,\n",euicc_total/PERF_REPEAT);
        fprintf(f,"LPA_total,%.2f,,\n",lpa_total/PERF_REPEAT);
        fprintf(f,"Server_total,%.2f,,\n",server_total/PERF_REPEAT);
        fclose(f);
        printf("Performance data -> perf_results.csv\n");
    }
    system("rm -rf /tmp/pqzk_perf");
}

static void run_dos_bench(void)
{
    printf("\n=== DoS Attack Prevention Benchmark ===\n");

    const char *nvram_dir = "/tmp/pqzk_dos";
    system("mkdir -p /tmp/pqzk_dos");

    uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES];
    poly_vec_t sk_s;
    PQC_GenKeyPair(pk_t, &sk_s);

    uint8_t eid[16]={0}, k_sym[32], k_tee[32], R_bio[32], salt[32], cred_kyc[64];
    pqzk_rand_bytes(k_sym, 32); pqzk_rand_bytes(k_tee, 32);
    pqzk_rand_bytes(R_bio, 32); pqzk_rand_bytes(salt,  32);
    pqzk_rand_bytes(cred_kyc, 64);

    beta_params_t params = PQZK_DEFAULT_BETA_PARAMS;

    // 生成测试数据
    poly_vec_t W_pub, W_sec, W;
    uint8_t seed_y[32], MAC_W[32];
    PQC_PreCompute(&W_pub, seed_y);
    
    // 初始化eUICC状态
    uint64_t init_ctr;
    pqzk_rand_bytes((uint8_t*)&init_ctr, 8);
    PQC_eUICC_Init(nvram_dir, eid, 16, &sk_s,
                   k_sym, 32, init_ctr, k_tee, 32,
                   salt, cred_kyc, 64);
    
    PQC_eUICC_Commit(nvram_dir, &W_sec, MAC_W);
    pqzk_vec_add(&W_sec, &W_pub, &W);

    uint8_t c_seed[32];
    pqzk_rand_bytes(c_seed, 32);
    poly_t c_agg;
    PQC_GenChallenge(&W, c_seed, &c_agg);

    // 读取nvram状态
    nvram_state_t st;
    nvram_read(nvram_dir, &st);
    uint8_t ctr_bytes[8];
    write_le64(ctr_bytes, st.ctr_local);

    // 生成R_dynamic
    pqzk_iov_t rdyn_iov[] = { { R_bio, 32 }, { ctr_bytes, 8 }, { NULL, 0 } };
    uint8_t R_dynamic[32];
    pqzk_sha256_iov(rdyn_iov, R_dynamic);

    uint8_t cagg_bytes[PQ_ZK_POLY_BYTES];
    PQC_EncodePoly(&c_agg, cagg_bytes);
    uint8_t hash_M2[32];
    pqzk_rand_bytes(hash_M2, 32);

    // 生成AuthToken
    pqzk_iov_t auth_iov[] = {
        { cagg_bytes, PQ_ZK_POLY_BYTES },
        { ctr_bytes,  8                },
        { R_dynamic,  32               },
        { hash_M2,    32               },
        { NULL, 0 }
    };
    uint8_t AuthToken[32];
    pqzk_hmac_sha256_iov(k_tee, auth_iov, AuthToken);

    // 计算z_sec_masked
    poly_vec_t z_sec_masked;
    PQC_ComputeZ_and_Mask(
        nvram_dir, &c_agg, c_seed,
        R_dynamic, hash_M2, AuthToken, &z_sec_masked);

    // 生成y_pub和resp_z
    poly_vec_t y_pub, resp_z;
    PQC_RegenerateYpub(seed_y, &y_pub);
    PQC_LPA_Aggregate(&z_sec_masked, &y_pub, &resp_z);

    // 生成M_mask
    poly_vec_t M_mask;
    PQC_GenerateMask(k_sym, c_seed, st.ctr_local, R_dynamic, &M_mask);

    // 预热
    for (int i = 0; i < 10; i++) {
        // MAC验证预热
        pqzk_hmac_sha256_iov(k_tee, auth_iov, AuthToken);
        
        // 完整格验证预热
        PQ_ZK_ErrorCode vrc = PQC_VerifyEngine(
            PQZK_MATRIX_A_SEED, pk_t, &W, &resp_z,
            c_seed, R_dynamic, &M_mask, &params);
    }

    // 测量MAC验证时间
    int trials = 1000;
    double mac_times[trials];
    for (int i = 0; i < trials; i++) {
        double t0 = get_time_us();
        pqzk_hmac_sha256_iov(k_tee, auth_iov, AuthToken);
        mac_times[i] = get_time_us() - t0;
    }

    // 测量完整格验证时间
    double lattice_times[trials];
    for (int i = 0; i < trials; i++) {
        double t0 = get_time_us();
        PQ_ZK_ErrorCode vrc = PQC_VerifyEngine(
            PQZK_MATRIX_A_SEED, pk_t, &W, &resp_z,
            c_seed, R_dynamic, &M_mask, &params);
        lattice_times[i] = get_time_us() - t0;
    }

    // 计算平均值
    double mac_avg = 0, lattice_avg = 0;
    for (int i = 0; i < trials; i++) {
        mac_avg += mac_times[i];
        lattice_avg += lattice_times[i];
    }
    mac_avg /= trials;
    lattice_avg /= trials;

    printf("\nDoS Prevention Performance:\n");
    printf("MAC_W Verification:    %.2f μs\n", mac_avg);
    printf("Full Lattice Verification: %.2f μs\n", lattice_avg);
    printf("Speedup:              %.1fX faster\n", lattice_avg / mac_avg);

    // 写入结果文件
    FILE *f = fopen("dos_results.csv", "w");
    if (f) {
        fprintf(f, "test,avg_us\n");
        fprintf(f, "MAC_W_Verification,%.2f\n", mac_avg);
        fprintf(f, "Full_Lattice_Verification,%.2f\n", lattice_avg);
        fprintf(f, "Speedup,%.2f\n", lattice_avg / mac_avg);
        fclose(f);
        printf("DoS benchmark data -> dos_results.csv\n");
    }

    system("rm -rf /tmp/pqzk_dos");
}

static void run_constant_time_bench(void)
{
    printf("\n=== Constant Time Execution Benchmark ===\n");

    const char *nvram_dir = "/tmp/pqzk_constant";
    system("mkdir -p /tmp/pqzk_constant");

    uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES];
    poly_vec_t sk_s;
    PQC_GenKeyPair(pk_t, &sk_s);

    uint8_t eid[16]={0}, k_sym[32], k_tee[32], R_bio[32], salt[32], cred_kyc[64];
    pqzk_rand_bytes(k_sym, 32); pqzk_rand_bytes(k_tee, 32);
    pqzk_rand_bytes(R_bio, 32); pqzk_rand_bytes(salt,  32);
    pqzk_rand_bytes(cred_kyc, 64);

    beta_params_t params = PQZK_DEFAULT_BETA_PARAMS;

    // 测量执行时间（CPU周期）
    int trials = 10000;
    double exec_times[trials];

    for (int i = 0; i < trials; i++) {
        // 每次使用不同的随机输入
        uint64_t init_ctr;
        pqzk_rand_bytes((uint8_t*)&init_ctr, 8);
        PQC_eUICC_Init(nvram_dir, eid, 16, &sk_s,
                       k_sym, 32, init_ctr, k_tee, 32,
                       salt, cred_kyc, 64);

        // 生成测试数据
        poly_vec_t W_pub, W_sec, W;
        uint8_t seed_y[32], MAC_W[32];
        PQC_PreCompute(&W_pub, seed_y);
        PQC_eUICC_Commit(nvram_dir, &W_sec, MAC_W);
        pqzk_vec_add(&W_sec, &W_pub, &W);

        uint8_t c_seed[32];
        pqzk_rand_bytes(c_seed, 32);
        poly_t c_agg;
        PQC_GenChallenge(&W, c_seed, &c_agg);

        // 读取nvram状态
        nvram_state_t st;
        nvram_read(nvram_dir, &st);
        uint8_t ctr_bytes[8];
        write_le64(ctr_bytes, st.ctr_local);

        // 生成R_dynamic
        pqzk_iov_t rdyn_iov[] = { { R_bio, 32 }, { ctr_bytes, 8 }, { NULL, 0 } };
        uint8_t R_dynamic[32];
        pqzk_sha256_iov(rdyn_iov, R_dynamic);

        uint8_t cagg_bytes[PQ_ZK_POLY_BYTES];
        PQC_EncodePoly(&c_agg, cagg_bytes);
        uint8_t hash_M2[32];
        pqzk_rand_bytes(hash_M2, 32);

        // 生成AuthToken
        pqzk_iov_t auth_iov[] = {
            { cagg_bytes, PQ_ZK_POLY_BYTES },
            { ctr_bytes,  8                },
            { R_dynamic,  32               },
            { hash_M2,    32               },
            { NULL, 0 }
        };
        uint8_t AuthToken[32];
        pqzk_hmac_sha256_iov(k_tee, auth_iov, AuthToken);

        // 测量核心代数响应生成时间
        poly_vec_t z_sec_masked;
        double t0 = get_time_us();
        PQ_ZK_ErrorCode rc = PQC_ComputeZ_and_Mask(
            nvram_dir, &c_agg, c_seed,
            R_dynamic, hash_M2, AuthToken, &z_sec_masked);
        exec_times[i] = get_time_us() - t0;
    }

    // 计算统计信息
    double avg = 0, min_val = 1e9, max_val = 0;
    for (int i = 0; i < trials; i++) {
        avg += exec_times[i];
        if (exec_times[i] < min_val) min_val = exec_times[i];
        if (exec_times[i] > max_val) max_val = exec_times[i];
    }
    avg /= trials;

    // 计算方差
    double variance = 0;
    for (int i = 0; i < trials; i++) {
        variance += (exec_times[i] - avg) * (exec_times[i] - avg);
    }
    variance /= trials;
    double std_dev = sqrt(variance);

    printf("\nConstant Time Execution Results (%d trials):\n", trials);
    printf("Average time: %.2f μs\n", avg);
    printf("Minimum time: %.2f μs\n", min_val);
    printf("Maximum time: %.2f μs\n", max_val);
    printf("Standard deviation: %.2f μs\n", std_dev);
    printf("Variance: %.2f μs²\n", variance);

    // 写入结果文件
    FILE *f = fopen("constant_time_results.csv", "w");
    if (f) {
        fprintf(f, "trial,execution_time_us\n");
        for (int i = 0; i < trials; i++) {
            fprintf(f, "%d,%.2f\n", i, exec_times[i]);
        }
        fclose(f);
        printf("Constant time data -> constant_time_results.csv\n");
    }

    system("rm -rf /tmp/pqzk_constant");
}

int main(int argc, char *argv[])
{
    int do_grid=0, do_perf=0, do_dos=0, do_constant=0;
    if(argc==1){ do_grid=do_perf=1; }
    else {
        for(int i=1;i<argc;i++){
            if(!strcmp(argv[i],"--grid")) do_grid=1;
            if(!strcmp(argv[i],"--perf")) do_perf=1;
            if(!strcmp(argv[i],"--dos")) do_dos=1;
            if(!strcmp(argv[i],"--constant")) do_constant=1;
        }
    }
    printf("============================================\n");
    printf("  PQ-ZK-eSIM bench v4.2\n");
    printf("  k=%d s=%.1f bf=%d bmin=%d\n",
           PQZK_KAPPA,(double)PQZK_SIGMA_PUB,
           PQZK_BETA_FINAL,PQZK_BETA_MIN);
    printf("============================================\n");
    if(do_perf) run_perf_bench();
    if(do_grid) run_grid_search();
    if(do_dos) run_dos_bench();
    if(do_constant) run_constant_time_bench();
    return 0;
}