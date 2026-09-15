[1mdiff --git a/README.txt b/README.txt[m
[1mindex f7271f5..85229ad 100644[m
[1m--- a/README.txt[m
[1m+++ b/README.txt[m
[36m@@ -144,7 +144,7 @@[m [mPQ-ZK-eSIM 把计算分给三方：[m
 | 参数 | 值 | 说明 |[m
 |---|---|---|[m
 | N | 256 | 环维度 |[m
[31m-| K × M | 5 × 8 | 矩阵维度 |[m
[32m+[m[32m| K × M | 3 × 8 | 矩阵维度 |[m
 | q | 8,380,417 | 模数（2²³ − 2¹³ + 1）|[m
 | κ | 35 | 挑战权重 |[m
 | σ_pub | 5,000 | 高斯淹没宽度 |[m
[36m@@ -157,8 +157,8 @@[m [mPQ-ZK-eSIM 把计算分给三方：[m
 - 抗量子不可伪造性（Module-SIS 归约 + low-density decisional SIS 假设）[m
 - eUICC 无 NTT（仅 mκN ≈ 7.17×10⁴ 次三元加法）[m
 - 生物特征不暴露（TEE 内限定，仅公开 Merkle 根）[m
[31m-- LPA 盲性（HKDF 派生密钥下的 PRF 掩码）[m
[31m-- 服务端视角可模拟性（高斯淹没，Rényi 散度界）[m
[32m+[m[32m- 恶意 LPA 场景：生物特征不暴露、活体门控与认证可靠性；不声明长期秘密的完整视图隐私[m
[32m+[m[32m- 诚实 LPA / 好奇服务器场景：高斯 flooding 的有限 Rényi 记账；渐近 UC 隐私按论文条件陈述[m
 - DoS 抗性（MAC 预过滤提前拒绝）[m
 - 前向保密（每会话 KDF 密钥演进）[m
 - 状态稳健性（滑动窗口 MAC 重同步，原子 NVRAM 写入）[m
[1mdiff --git a/artifact/terminal/euicc/benchmarks/bench_pqzkesim.c b/artifact/terminal/euicc/benchmarks/bench_pqzkesim.c[m
[1mindex 384d31a..3cef07a 100644[m
[1m--- a/artifact/terminal/euicc/benchmarks/bench_pqzkesim.c[m
[1m+++ b/artifact/terminal/euicc/benchmarks/bench_pqzkesim.c[m
[36m@@ -23,15 +23,18 @@[m [mstatic int norm_precheck(const poly_vec_t *z_unmasked,[m
 {[m
     int32_t inf_norm = 0;[m
     int64_t l2_sq    = 0;[m
[32m+[m[32m    int64_t l1_norm  = 0;[m
     for (int i = 0; i < PQ_ZK_M * PQ_ZK_N; i++) {[m
         int32_t v  = (int32_t)z_unmasked->coeffs[i];[m
         int32_t av = (v < 0) ? -v : v;[m
         if (av > inf_norm) inf_norm = av;[m
         l2_sq += (int64_t)v * v;[m
[32m+[m[32m        l1_norm += (int64_t)av;[m
     }[m
     if (l2_sq < (int64_t)params->beta_min * params->beta_min) return 2;[m
     if (l2_sq > (int64_t)params->beta_final * params->beta_final) return 1;[m
     if (inf_norm > (int32_t)PQ_ZK_BETA_INF) return 1;[m
[32m+[m[32m    if (params->beta_l1 > 0 && l1_norm < (int64_t)params->beta_l1) return 2;[m
     return 0;[m
 }[m
 [m
[36m@@ -171,6 +174,7 @@[m [mstatic void run_grid_search(void)[m
             beta_params_t params;[m
             params.beta_final = (uint32_t)beta_final;[m
             params.beta_min   = PQZK_BETA_MIN;[m
[32m+[m[32m            params.beta_l1    = PQZK_BETA_L1;[m
 [m
             int    overflow_fail  = 0;[m
             int    underflow_fail = 0;[m
[1mdiff --git a/artifact/terminal/euicc/benchmarks/bench_pqzkesim_comprehensive.c b/artifact/terminal/euicc/benchmarks/bench_pqzkesim_comprehensive.c[m
[1mindex 9c33592..e784bf4 100644[m
[1m--- a/artifact/terminal/euicc/benchmarks/bench_pqzkesim_comprehensive.c[m
[1m+++ b/artifact/terminal/euicc/benchmarks/bench_pqzkesim_comprehensive.c[m
[36m@@ -100,9 +100,12 @@[m [mstatic void make_sparse_ypub(const uint8_t seed[PQ_ZK_SEED_BYTES],double rho,pol[m
     for(int i=0;i<PQ_ZK_M*PQ_ZK_N;i++){uint8_t rb;pqzk_rand_bytes(&rb,1);if((double)rb/255.0>rho)out->coeffs[i]=0;}}[m
 [m
 static void run_sparse_noise_attack_experiment(void){[m
[31m-    printf("\n=== Sparse Noise Attack ===\n");[m
[32m+[m[32m    printf("\n=== Sparse Noise Attack (consistent malicious-y_pub model) ===\n");[m
     FILE*csv=fopen("sparse_noise_attack_results.csv","w");if(!csv){perror("fopen");return;}[m
[32m+[m[32m    FILE*detail=fopen("sparse_noise_norm_breakdown.csv","w");if(!detail){perror("fopen");fclose(csv);return;}[m
[32m+[m[32m    /* Keep the legacy 4-column result schema so existing plot/validation scripts keep working. */[m
     fprintf(csv,"rho,detection_rate,false_reject_rate,avg_total_us\n");[m
[32m+[m[32m    fprintf(detail,"rho,l2_low_rate,l2_high_rate,linf_rate,l1_low_rate,verify_reject_rate\n");[m
     const char*nd="/tmp/pqzk_sparse";system("mkdir -p /tmp/pqzk_sparse");[m
     uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES];poly_vec_t sk_s;PQC_GenKeyPair(pk_t,&sk_s);[m
     uint8_t eid[16]={0},k_sym[32],k_tee[32],d_seed[32],R_bio[32],salt[32],cred_kyc[PQZK_MLDSA_SIG_BYTES];[m
[36m@@ -111,14 +114,23 @@[m [mstatic void run_sparse_noise_attack_experiment(void){[m
     double rhos[]={0.0,0.05,0.10,0.25,0.50,0.75,0.90,1.0};int nr=(int)(sizeof(rhos)/sizeof(rhos[0]));[m
     beta_params_t params=PQZK_DEFAULT_BETA_PARAMS;[m
     for(int ri=0;ri<nr;ri++){[m
[31m-        double rho=rhos[ri];int trials=200,detected=0,accepted=0,false_rej=0;double sum_us=0.0;[m
[32m+[m[32m        double rho=rhos[ri];int trials=200,detected=0,accepted=0,false_rej=0;[m
[32m+[m[32m        int l2lo=0,l2hi=0,linf=0,l1lo=0,vrej=0; double sum_us=0.0;[m
         printf("  rho=%.2f ... ",rho);fflush(stdout);[m
[31m-        for(int r=0;r<trials;r++){[m
[32m+[m[32m        for(int rr=0;rr<trials;rr++){[m
             uint64_t c0;pqzk_rand_bytes((uint8_t*)&c0,8);[m
             PQC_eUICC_Init(nd,eid,16,&sk_s,k_sym,32,c0,k_tee,32,salt,R_bio,cred_kyc,64);[m
             nvram_state_t st;nvram_read(nd,&st);uint64_t ctr=st.ctr_local;[m
[31m-            poly_vec_t Wp,Ws,W;uint8_t sy[PQ_ZK_SEED_BYTES],MW[PQ_ZK_MAC_BYTES];[m
[31m-            PQC_PreCompute(&Wp,sy);PQC_eUICC_Commit(nd,&Ws,MW);pqzk_vec_add(&Ws,&Wp,&W, PQ_ZK_K);[m
[32m+[m
[32m+[m[32m            /* Malicious LPA fixes structured y_pub before W and challenge. */[m
[32m+[m[32m            uint8_t sy[PQ_ZK_SEED_BYTES];pqzk_rand_bytes(sy,sizeof(sy));[m
[32m+[m[32m            poly_vec_t ya;make_sparse_ypub(sy,rho,&ya);[m
[32m+[m[32m            poly_vec_t A_rows[PQ_ZK_K],Wp;[m
[32m+[m[32m            pqzk_gen_matrix_A(PQZK_MATRIX_A_SEED,A_rows,PQ_ZK_K,PQ_ZK_M);[m
[32m+[m[32m            pqzk_mat_vec_mul_ntt(A_rows,&ya,&Wp,PQ_ZK_K,PQ_ZK_M);[m
[32m+[m
[32m+[m[32m            poly_vec_t Ws,W;uint8_t MW[PQ_ZK_MAC_BYTES];[m
[32m+[m[32m            PQC_eUICC_Commit(nd,&Ws,MW);pqzk_vec_add(&Ws,&Wp,&W,PQ_ZK_K);[m
             uint8_t cs[PQ_ZK_SEED_BYTES];pqzk_rand_bytes(cs,PQ_ZK_SEED_BYTES);[m
             poly_t ca;PQC_GenChallenge(&W,cs,&ca);[m
             uint8_t cb[8];write_le64(cb,ctr);uint8_t Rd[32];[m
[36m@@ -126,31 +138,39 @@[m [mstatic void run_sparse_noise_attack_experiment(void){[m
             uint8_t tok[PQ_ZK_MAC_BYTES];build_auth_token(k_tee,&ca,ctr,Rd,tok);[m
             poly_vec_t zsm;[m
             if(PQC_ComputeZ_and_Mask(nd,&ca,cs,Rd,tok,&zsm)!=PQ_ZK_SUCCESS)continue;[m
[32m+[m
             double t0=get_time_us();[m
[31m-            poly_vec_t ya,rz;PQC_RegenerateYpub(sy,&ya);PQC_LPA_Aggregate(&zsm,&ya,&rz);[m
[32m+[m[32m            poly_vec_t rz;PQC_LPA_Aggregate(&zsm,&ya,&rz);[m
             poly_vec_t Mm;PQC_GenerateMask(k_sym,cs,ctr,Rd,&Mm);[m
[31m-            poly_vec_t zmm,zu;pqzk_vec_sub(&rz,&Mm,&zmm, PQ_ZK_M);[m
[31m-            for(int i=0;i<PQ_ZK_M*PQ_ZK_N;i++){int32_t v=zmm.coeffs[i];if(v>PQ_ZK_Q_VAL/2)v-=PQ_ZK_Q_VAL;zu.coeffs[i]=v;}[m
[31m-            if (rho < 1.0) {[m
[31m-                for(int i=0;i<PQ_ZK_M*PQ_ZK_N;i++){[m
[31m-                    uint8_t rb; pqzk_rand_bytes(&rb,1);[m
[31m-                    if((double)rb/255.0>rho)zu.coeffs[i]=0;[m
[31m-                }[m
[32m+[m[32m            poly_vec_t zmm,zu;pqzk_vec_sub(&rz,&Mm,&zmm,PQ_ZK_M);[m
[32m+[m[32m            int32_t inf=0;int64_t l2=0,l1=0;[m
[32m+[m[32m            for(int i=0;i<PQ_ZK_M*PQ_ZK_N;i++){[m
[32m+[m[32m                int32_t v=zmm.coeffs[i];if(v>PQ_ZK_Q_VAL/2)v-=PQ_ZK_Q_VAL;zu.coeffs[i]=v;[m
[32m+[m[32m                int32_t av=v<0?-v:v;if(av>inf)inf=av;l2+=(int64_t)v*v;l1+=av;[m
             }[m
[31m-            PQ_ZK_ErrorCode vr = PQC_VerifyEngine(PQZK_MATRIX_A_SEED,pk_t,&W,&rz,cs,Rd,&Mm,&params);[m
[31m-            if(vr==PQ_ZK_SUCCESS)accepted++; else false_rej++;[m
[32m+[m[32m            int f_l2lo=l2<(int64_t)params.beta_min*params.beta_min;[m
[32m+[m[32m            int f_l2hi=l2>(int64_t)params.beta_final*params.beta_final;[m
[32m+[m[32m            int f_inf=inf>(int32_t)PQ_ZK_BETA_INF;[m
[32m+[m[32m            int f_l1=params.beta_l1>0&&l1<(int64_t)params.beta_l1;[m
[32m+[m[32m            if(f_l2lo)l2lo++;if(f_l2hi)l2hi++;if(f_inf)linf++;if(f_l1)l1lo++;[m
[32m+[m[32m            if(f_l2lo||f_l2hi||f_inf||f_l1)detected++;[m
 [m
[31m-            int d1=0,d2=0,lh=0;[m
[31m-            int64_t actual_l1 = 0;[m
[31m-            for(int i=0;i<PQ_ZK_M*PQ_ZK_N;i++){int32_t v = zu.coeffs[i]; actual_l1 += (v < 0) ? -v : v;}[m
[31m-            if (actual_l1 < (int64_t)params.beta_l1) detected++;[m
[31m-            norm_precheck(&zu,&params,&d1,&d2,&lh);[m
[31m-            sum_us+=get_time_us()-t0;}[m
[32m+[m[32m            PQ_ZK_ErrorCode vr=PQC_VerifyEngine(PQZK_MATRIX_A_SEED,pk_t,&W,&rz,cs,Rd,&Mm,&params);[m
[32m+[m[32m            if(vr==PQ_ZK_SUCCESS)accepted++;else vrej++;[m
[32m+[m[32m            if(rho>=0.999 && vr!=PQ_ZK_SUCCESS)false_rej++;[m
[32m+[m[32m            sum_us+=get_time_us()-t0;[m
[32m+[m[32m        }[m
         double dr=(double)detected/trials,fr=(double)false_rej/trials,avg=sum_us/trials;[m
         fprintf(csv,"%.2f,%.6f,%.6f,%.2f\n",rho,dr,fr,avg);[m
[31m-        printf("detected=%.1f%% accepted=%.1f%% avg=%.1fus\n",dr*100,(double)accepted/trials*100,avg);}[m
[31m-    fclose(csv);system("rm -rf /tmp/pqzk_sparse");printf("-> sparse_noise_attack_results.csv\n");}[m
[31m-[m
[32m+[m[32m        fprintf(detail,"%.2f,%.6f,%.6f,%.6f,%.6f,%.6f\n",[m
[32m+[m[32m                rho,(double)l2lo/trials,(double)l2hi/trials,[m
[32m+[m[32m                (double)linf/trials,(double)l1lo/trials,(double)vrej/trials);[m
[32m+[m[32m        printf("detected=%.1f%% accepted=%.1f%% honestFRR=%.2f%% avg=%.1fus\n",[m
[32m+[m[32m               dr*100,(double)accepted/trials*100,fr*100,avg);[m
[32m+[m[32m    }[m
[32m+[m[32m    fclose(csv);fclose(detail);system("rm -rf /tmp/pqzk_sparse");[m
[32m+[m[32m    printf("-> sparse_noise_attack_results.csv, sparse_noise_norm_breakdown.csv\n");[m
[32m+[m[32m}[m
 static void run_sliding_window_resync_experiment(void){[m
     printf("\n=== Sliding Window Resync ===\n");[m
     FILE*csv=fopen("sliding_window_resync_results.csv","w");if(!csv){perror("fopen");return;}[m
[36m@@ -359,7 +379,7 @@[m [mint main(int argc,char*argv[]){[m
         if(!strcmp(argv[i],"--only") && i+1<argc){ only=argv[++i]; }[m
     }[m
     printf("============================================\n");[m
[31m-    printf("  PQ-ZK-eSIM Experiments v5.1\n");[m
[32m+[m[32m    printf("  PQ-ZK-eSIM Experiments camera-ready k=3,m=8\n");[m
     printf("============================================\n");[m
     int run_all = (only == NULL);[m
     if(run_all || (only && !strcmp(only,"nvm")))     run_nvm_wear_experiment();[m
[1mdiff --git a/artifact/terminal/euicc/include/pq_zk_esim.h b/artifact/terminal/euicc/include/pq_zk_esim.h[m
[1mindex 84a8f49..81bc49d 100644[m
[1m--- a/artifact/terminal/euicc/include/pq_zk_esim.h[m
[1m+++ b/artifact/terminal/euicc/include/pq_zk_esim.h[m
[36m@@ -12,7 +12,7 @@[m [mextern "C" {[m
 #endif[m
 [m
 #define PQ_ZK_N 256[m
[31m-#define PQ_ZK_K 5[m
[32m+[m[32m#define PQ_ZK_K 3[m
 #define PQ_ZK_M 8[m
 #define PQ_ZK_SEED_BYTES 32[m
 #define PQ_ZK_TEE_KEY_BYTES 32[m
[1mdiff --git a/artifact/terminal/euicc/src/algebra/pq_zk_poly.c b/artifact/terminal/euicc/src/algebra/pq_zk_poly.c[m
[1mindex 81c3a9a..62d05a8 100644[m
[1m--- a/artifact/terminal/euicc/src/algebra/pq_zk_poly.c[m
[1m+++ b/artifact/terminal/euicc/src/algebra/pq_zk_poly.c[m
[36m@@ -81,7 +81,7 @@[m [mstatic double approx_normal(uint64_t r1, uint64_t r2)[m
 [m
 /* ================================================================[m
  * SampleGauss_sigma: Gaussian sampling for y_pub[m
[31m- * M=8 polynomials, sigma=5000, truncation at beta_inf=35700[m
[32m+[m[32m * M=8 polynomials, sigma=5000; verifier applies beta_inf=35700[m
  * NOTE: Box-Muller continuous Gaussian + rounding is an approximation[m
  *       of a discrete Gaussian sampler (not a rigorous CDT/Knuth-Yao[m
  *       sampler). This is consistent with the paper, whose finite[m
[36m@@ -98,8 +98,6 @@[m [mvoid pqzk_sample_gauss_vec(const uint8_t *seed, size_t seed_len,[m
     pqzk_shake256(seed, seed_len, buf, needed);[m
 [m
     int total = PQ_ZK_M * PQ_ZK_N;[m
[31m-    double tau_bound = (double)PQ_ZK_BETA_INF;[m
[31m-[m
     for (int i = 0; i < total; i++) {[m
         uint64_t r1, r2;[m
         memcpy(&r1, buf + i * 16,     8);[m
[36m@@ -107,8 +105,6 @@[m [mvoid pqzk_sample_gauss_vec(const uint8_t *seed, size_t seed_len,[m
 [m
         double g = approx_normal(r1, r2) * PQ_ZK_SIGMA_PUB;[m
         int32_t v = (int32_t)round(g);[m
[31m-        if (v >  (int32_t)tau_bound) v =  (int32_t)tau_bound;[m
[31m-        if (v < -(int32_t)tau_bound) v = -(int32_t)tau_bound;[m
 [m
         v = v % PQ_ZK_Q_VAL;[m
         if (v < 0) v += PQ_ZK_Q_VAL;[m
[36m@@ -120,101 +116,110 @@[m [mvoid pqzk_sample_gauss_vec(const uint8_t *seed, size_t seed_len,[m
 }[m
 [m
 /* ================================================================[m
[31m- * Parse_R_q^m: PRF stream -> uniform poly vector (M_mask)[m
[31m- * M=8 polynomials, 24-bit packing (q=8.38M < 2^24)[m
[32m+[m[32m * Parse_R_q^m: PRF stream -> uniform poly vector (M_mask).[m
[32m+[m[32m * Parse 23-bit blocks (ceil(log2 q)=23) and rejection-sample v<q.[m
[32m+[m[32m * Callers provide 128 spare candidates; exhaustion is fail-closed to zero.[m
  * ================================================================ */[m
 void pqzk_parse_poly_vec(const uint8_t *stream, size_t stream_len,[m
                           poly_vec_t *out)[m
 {[m
     size_t pos = 0;[m
     int total = PQ_ZK_M * PQ_ZK_N;[m
[31m-[m
[31m-    for (int i = 0; i < total; i++) {[m
[31m-        uint32_t v;[m
[31m-        do {[m
[31m-            if (pos + 3 >= stream_len) pos = 0;[m
[31m-            v = (uint32_t)stream[pos][m
[31m-              | ((uint32_t)stream[pos + 1] << 8)[m
[31m-              | ((uint32_t)stream[pos + 2] << 16);[m
[31m-            pos += 3;[m
[31m-        } while (v >= PQ_ZK_Q_VAL);[m
[31m-[m
[31m-        out->coeffs[i] = (int32_t)((int32_t)v);[m
[32m+[m[32m    int filled = 0;[m
[32m+[m[32m    while (filled < total) {[m
[32m+[m[32m        if (pos + 3 > stream_len) {[m
[32m+[m[32m            memset(&out->coeffs[filled], 0,[m
[32m+[m[32m                   (size_t)(total - filled) * sizeof(out->coeffs[0]));[m
[32m+[m[32m            return;[m
[32m+[m[32m        }[m
[32m+[m[32m        uint32_t v = ((uint32_t)stream[pos][m
[32m+[m[32m                    | ((uint32_t)stream[pos + 1] << 8)[m
[32m+[m[32m                    | ((uint32_t)stream[pos + 2] << 16)) & 0x7FFFFFu;[m
[32m+[m[32m        pos += 3;[m
[32m+[m[32m        if (v >= PQ_ZK_Q_VAL) continue;[m
[32m+[m[32m        out->coeffs[filled++] = (int32_t)v;[m
     }[m
 }[m
[31m-[m
 /* ================================================================[m
[31m- * gen_matrix_A: K x M rectangular matrix (5 x 8)[m
[31m- * A_rows[i].coeffs[j*N .. j*N+N-1] = A[i][j][m
[31m- * i=0..K-1, j=0..M-1[m
[32m+[m[32m * gen_matrix_A: systematic public matrix A=[Abar|I_k].[m
[32m+[m[32m * Abar is k x (m-k), expanded uniformly with 23-bit rejection sampling.[m
  * ================================================================ */[m
[32m+[m[32mstatic void sample_uniform_matrix_poly(const uint8_t seed[32], int row, int col,[m
[32m+[m[32m                                       int32_t out[PQ_ZK_N])[m
[32m+[m[32m{[m
[32m+[m[32m    uint8_t domain[38];[m
[32m+[m[32m    uint8_t buf[384];[m
[32m+[m[32m    uint32_t block = 0;[m
[32m+[m[32m    int filled = 0;[m
[32m+[m[32m    memcpy(domain, seed, 32);[m
[32m+[m[32m    domain[32] = (uint8_t)row;[m
[32m+[m[32m    domain[33] = (uint8_t)