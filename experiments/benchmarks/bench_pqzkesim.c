/*
 * bench_pqzkesim.c — v4.0
 * 参数网格搜索 + 性能基准测试
 *
 * v4.0 变化：
 *   - H_ctx 全部替换为 R_dynamic
 *   - R_dynamic = SHA256(R_bio || ctr_local)，在每次试验中派生
 *   - ctr 初始值随机
 *   - PQC_GenChallenge 调用无 H_ctx 参数
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

/* timings[0]=PreCompute, [1]=eUICC_Commit, [2]=GenChallenge,
 * [3]=ComputeZ_and_Mask, [4]=LPA_Aggregate, [5]=GenerateMask+Verify */
static int run_one_trial(const char *nvram_dir,
                          const uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES],
                          const uint8_t k_sym[32],
                          const uint8_t k_tee[32],
                          const uint8_t R_bio[32],
                          const uint8_t eid[16],  
                          const poly_vec_t *sk_s,
                          beta_params_t *params,
                          double timings[6])
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

    /* ---- 阶段二（v4.0：无 H_ctx）---- */
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

    /* R_dynamic = SHA256(R_bio || ctr_local) */
    pqzk_iov_t rdyn_iov[] = { { R_bio, 32 }, { ctr_bytes, 8 }, { NULL, 0 } };
    uint8_t R_dynamic[32];
    pqzk_sha256_iov(rdyn_iov, R_dynamic);

    /* AuthToken = HMAC(K_TEE, encode(c_agg)||ctr_le8||R_dynamic||hash_M2) */
    uint8_t cagg_bytes[PQ_ZK_POLY_BYTES];
    PQC_EncodePoly(&c_agg, cagg_bytes);
    uint8_t hash_M2[32];
    pqzk_rand_bytes(hash_M2, 32);

    pqzk_iov_t auth_iov[] = {
        { cagg_bytes, PQ_ZK_POLY_BYTES },
        { ctr_bytes,  8                },
        { R_dynamic,  32               },   /* v4.0 */
        { hash_M2,    32               },
        { NULL, 0 }
    };
    uint8_t AuthToken[32];
    pqzk_hmac_sha256_iov(k_tee, auth_iov, AuthToken);

    /* ---- 阶段四（v4.0：传 R_dynamic）---- */
    poly_vec_t z_sec_masked;
    t0 = get_time_us();
    PQ_ZK_ErrorCode rc = PQC_ComputeZ_and_Mask(
        nvram_dir, &c_agg, c_seed,
        R_dynamic,    /* v4.0 */
        hash_M2, AuthToken, &z_sec_masked);
    timings[3] = get_time_us() - t0;
    if (rc != PQ_ZK_SUCCESS) return 0;

    /* ---- 阶段五 ---- */
    poly_vec_t y_pub, resp_z;
    PQC_RegenerateYpub(seed_y, &y_pub);
    t0 = get_time_us();
    PQC_LPA_Aggregate(&z_sec_masked, &y_pub, &resp_z);
    timings[4] = get_time_us() - t0;

    /* ---- 阶段六：服务器重构 R_dynamic ---- */
    poly_vec_t M_mask;
    t0 = get_time_us();
    /* 服务器用 ctr_session = st.ctr_local，R_dynamic 已知 */
    PQC_GenerateMask(k_sym, c_seed, st.ctr_local, R_dynamic, &M_mask);

    PQ_ZK_ErrorCode vrc = PQC_VerifyEngine(
        PQZK_MATRIX_A_SEED, pk_t, &W, &resp_z,
        c_seed, R_dynamic, &M_mask, params);
    timings[5] = get_time_us() - t0;

    return (vrc == PQ_ZK_SUCCESS) ? 1 : 0;
}

/* ================================================================
 * 网格搜索
 * ================================================================ */
static void run_grid_search(void)
{
    printf("\n=== 参数网格搜索 (v4.0) ===\n");

    FILE *csv = fopen("grid_results.csv", "w");
    if (!csv) { perror("fopen"); return; }
    fprintf(csv, "kappa,sigma_pub,beta_final,beta_pub,correctness_ok,"
            "fail_count,trials,fail_rate,"
            "avg_precompute_us,avg_commit_us,avg_challenge_us,"
            "avg_compute_mask_us,avg_aggregate_us,avg_verify_us,avg_total_us\n");

    const char *nvram_dir = "/tmp/pqzk_bench_nvram";
    system("mkdir -p /tmp/pqzk_bench_nvram");

    uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES];
    poly_vec_t sk_s;
    PQC_GenKeyPair(pk_t, &sk_s);

    uint8_t eid[16]  = {0}; 
    uint8_t k_sym[32], k_tee[32], R_bio[32],salt[32],cred_kyc[64];
    pqzk_rand_bytes(k_sym,  32);
    pqzk_rand_bytes(k_tee,  32);
    pqzk_rand_bytes(R_bio,  32);
    pqzk_rand_bytes(salt, 32);
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

            int    fail_count = 0;
            double sum_t[6]   = {0};

            for (int trial = 0; trial < PQZK_GRID_TRIALS; trial++) {
                /* v4.0：ctr 初始值随机 */
                uint64_t init_ctr;
                pqzk_rand_bytes((uint8_t*)&init_ctr, 8);
                PQC_eUICC_Init(nvram_dir, eid, 16, &sk_s,
                               k_sym, 32, init_ctr, k_tee, 32,
                               salt,cred_kyc,64);

                double t[6] = {0};
                if (!run_one_trial(nvram_dir, pk_t, k_sym, k_tee,
                                   R_bio, eid, &sk_s, &params, t))
                    fail_count++;
                for (int i = 0; i < 6; i++) sum_t[i] += t[i];
            }

            double rate = (double)fail_count / PQZK_GRID_TRIALS;
            double tot  = 0; for(int i=0;i<6;i++) tot += sum_t[i]/PQZK_GRID_TRIALS;

            fprintf(csv, "%d,%.1f,%d,%d,%d,%d,%d,%.6f,"
                    "%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f\n",
                    kappa, sigma, beta_final, beta_pub, ok,
                    fail_count, PQZK_GRID_TRIALS, rate,
                    sum_t[0]/PQZK_GRID_TRIALS, sum_t[1]/PQZK_GRID_TRIALS,
                    sum_t[2]/PQZK_GRID_TRIALS, sum_t[3]/PQZK_GRID_TRIALS,
                    sum_t[4]/PQZK_GRID_TRIALS, sum_t[5]/PQZK_GRID_TRIALS, tot);

            if (fail_count > 0 || kappa == PQZK_KAPPA)
                printf("κ=%2d σ=%5.1f β=%4d ok=%d fail=%3d/%d rate=%.4f\n",
                       kappa, sigma, beta_final, ok,
                       fail_count, PQZK_GRID_TRIALS, rate);
            total++;
        }
    }
    fclose(csv);
    system("rm -rf /tmp/pqzk_bench_nvram");
    printf("共 %d 组，结果写入 grid_results.csv\n", total);
}

/* ================================================================
 * 性能基准
 * ================================================================ */
#define PERF_WARMUP 10
#define PERF_REPEAT 100

static void run_perf_bench(void)
{
    printf("\n=== 性能基准 v4.0 (κ=%d, σ=%.1f, %d次) ===\n",
           PQZK_KAPPA, PQZK_SIGMA_PUB, PERF_REPEAT);

    const char *nvram_dir = "/tmp/pqzk_perf";
    system("mkdir -p /tmp/pqzk_perf");

    uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES];
    poly_vec_t sk_s;
    PQC_GenKeyPair(pk_t, &sk_s);

    uint8_t eid[16]={0}, k_sym[32], k_tee[32], R_bio[32],salt[32],cred_kyc[64];
    pqzk_rand_bytes(k_sym,32); 
    pqzk_rand_bytes(k_tee,32); 
    pqzk_rand_bytes(R_bio,32);
    pqzk_rand_bytes(salt, 32);
    pqzk_rand_bytes(cred_kyc, 64);

    beta_params_t params = PQZK_DEFAULT_BETA_PARAMS;

    for (int i = 0; i < PERF_WARMUP; i++) {
        uint64_t c; pqzk_rand_bytes((uint8_t*)&c, 8);
        PQC_eUICC_Init(nvram_dir, eid, 16, &sk_s, k_sym, 32, c, k_tee, 32,salt,cred_kyc,64);
        double t[6];
        run_one_trial(nvram_dir, pk_t, k_sym, k_tee, R_bio, eid, &sk_s, &params, t);
    }

    double sum[6]={0}, min_t[6], max_t[6];
    for(int i=0;i<6;i++){min_t[i]=1e9; max_t[i]=0;}
    int ok_count = 0;

    for (int r = 0; r < PERF_REPEAT; r++) {
        uint64_t c; pqzk_rand_bytes((uint8_t*)&c, 8);
        PQC_eUICC_Init(nvram_dir, eid, 16, &sk_s, k_sym, 32, c, k_tee, 32,salt,cred_kyc,64);
        double t[6];
        if (run_one_trial(nvram_dir, pk_t, k_sym, k_tee, R_bio, eid, &sk_s, &params, t))
            ok_count++;
        for(int i=0;i<6;i++){
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
    printf("\n%-36s %8s %8s %8s\n","函数","avg(μs)","min","max");
    printf("%-36s %8s %8s %8s\n","----","-------","---","---");
    for(int i=0;i<6;i++){
        double avg = sum[i]/PERF_REPEAT;
        total_avg += avg;
        printf("%-36s %8.1f %8.1f %8.1f\n", names[i], avg, min_t[i], max_t[i]);
    }
    printf("%-36s %8.1f\n","端到端合计",total_avg);
    printf("\n成功率: %d/%d = %.1f%%\n", ok_count, PERF_REPEAT,
           100.0*ok_count/PERF_REPEAT);

    FILE *f = fopen("perf_results.csv","w");
    if(f){
        fprintf(f,"function,avg_us,min_us,max_us\n");
        for(int i=0;i<6;i++)
            fprintf(f,"%s,%.2f,%.2f,%.2f\n", names[i],
                    sum[i]/PERF_REPEAT, min_t[i], max_t[i]);
        fprintf(f,"total,%.2f,,\n", total_avg);
        fclose(f);
        printf("性能数据写入 perf_results.csv\n");
    }
    system("rm -rf /tmp/pqzk_perf");
}

int main(int argc, char *argv[])
{
    int do_grid=0, do_perf=0;
    if(argc==1){ do_grid=do_perf=1; }
    else {
        for(int i=1;i<argc;i++){
            if(!strcmp(argv[i],"--grid")) do_grid=1;
            if(!strcmp(argv[i],"--perf")) do_perf=1;
        }
    }
    printf("============================================\n");
    printf("  PQ-ZK-eSIM bench v4.0\n");
    printf("  κ=%d σ=%.1f β_final=%d β_min=%d\n",
           PQZK_KAPPA,(double)PQZK_SIGMA_PUB,PQZK_BETA_FINAL,PQZK_BETA_MIN);
    printf("============================================\n");
    if(do_perf) run_perf_bench();
    if(do_grid) run_grid_search();
    return 0;
}