#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <math.h>
#include <stdint.h>
#ifdef __linux__
#include <sys/resource.h>
#endif
#include "pq_zk_esim.h"
#include "pqzk_internal.h"
#include "pqzk_merkle.h"

extern int mode_switch(const char*,const uint8_t[PQZK_MNO_ID_BYTES],const uint8_t[PQZK_MNO_ID_BYTES]);

static double get_time_us(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return(double)ts.tv_sec*1e6+(double)ts.tv_nsec/1e3;}
static long get_rss_kb(void) {
    FILE* fp = fopen("/proc/self/status", "r");
    if (!fp) return 0;
    char line[256];
    long rss = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            rss = atol(line + 6);
            break;
        }
    }
    fclose(fp);
    return rss;
}

static int norm_precheck(const poly_vec_t*z,const beta_params_t*p,int*ov,int*un,int*l1){
    int32_t inf=0;int64_t l2=0,l1n=0;
    for(int i=0;i<PQ_ZK_M*PQ_ZK_N;i++){int32_t v=z->coeffs[i],av=v<0?-v:v;if(av>inf)inf=av;l2+=(int64_t)v*v;l1n+=av;}
    if(l2<(int64_t)p->beta_min*p->beta_min){if(un)(*un)++;return 2;}
    if(l2>(int64_t)p->beta_final*p->beta_final){if(ov)(*ov)++;return 1;}
    if(inf>(int32_t)PQ_ZK_BETA_INF){if(ov)(*ov)++;return 1;}
    if(p->beta_l1>0&&l1n<(int64_t)p->beta_l1){if(l1)(*l1)++;return 3;}
    return 0;}

static void build_auth_token(const uint8_t k_tee[32],const poly_t*c_agg,uint64_t ctr,const uint8_t R_dyn[32],uint8_t tok[PQ_ZK_MAC_BYTES]){
    uint8_t cb[PQ_ZK_POLY_BYTES],ctrb[8];
    PQC_EncodePoly(c_agg,cb);write_le64(ctrb,ctr);
    pqzk_iov_t iov[]={{cb,PQ_ZK_POLY_BYTES},{ctrb,8},{R_dyn,PQ_ZK_SEED_BYTES},{NULL,0}};
    pqzk_aes256_cmac(k_tee,iov,tok);}

static PQ_ZK_ErrorCode run_one_trial(
    const char*nvram,const uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES],
    const uint8_t k_sym_before[32],const uint8_t k_tee[32],
    const uint8_t d_seed[32],const uint8_t eid[16],const uint8_t R_bio[32],
    beta_params_t*params,double timings[7],
    int*ov,int*un,int*l1,uint8_t k_sym_out[32],uint64_t*ctr_out)
{
    double t0;
    nvram_state_t st;if(nvram_read(nvram,&st)!=0)return PQ_ZK_ERR_INVALID_PARAM;
    uint64_t ctr_local=st.ctr_local;if(ctr_out)*ctr_out=ctr_local;
    uint8_t k_sym_nvram[32];
    memcpy(k_sym_nvram, st.k_sym, 32);

    poly_vec_t W_pub,W_sec;uint8_t seed_y[PQ_ZK_SEED_BYTES],MAC_W[PQ_ZK_MAC_BYTES];
    t0=get_time_us();PQC_PreCompute(&W_pub,seed_y);timings[0]=get_time_us()-t0;
    t0=get_time_us();PQC_eUICC_Commit(nvram,&W_sec,MAC_W);timings[1]=get_time_us()-t0;
    poly_vec_t W;pqzk_vec_add(&W_sec,&W_pub,&W, PQ_ZK_K);

    uint8_t c_seed[PQ_ZK_SEED_BYTES];pqzk_rand_bytes(c_seed,PQ_ZK_SEED_BYTES);
    poly_t c_agg;
    t0=get_time_us();PQC_GenChallenge(&W,c_seed,&c_agg);timings[2]=get_time_us()-t0;

    uint8_t ctrb[8];write_le64(ctrb,ctr_local);
    uint8_t R_dyn[32];
    pqzk_iov_t rdyn[]={{R_bio,32},{ctrb,8},{NULL,0}};
    t0=get_time_us();pqzk_sha3_256_iov(rdyn,R_dyn);
    uint8_t tok[PQ_ZK_MAC_BYTES];build_auth_token(k_tee,&c_agg,ctr_local,R_dyn,tok);timings[3]=get_time_us()-t0;

    poly_vec_t zsm;
    t0=get_time_us();
    PQ_ZK_ErrorCode rc=PQC_ComputeZ_and_Mask(nvram,&c_agg,c_seed,R_dyn,tok,&zsm);
    timings[4]=get_time_us()-t0;
    if(rc!=PQ_ZK_SUCCESS){if(k_sym_out)memcpy(k_sym_out,k_sym_before,32);return rc;}

    poly_vec_t ypub,resp_z;PQC_RegenerateYpub(seed_y,&ypub);
    t0=get_time_us();PQC_LPA_Aggregate(&zsm,&ypub,&resp_z);timings[5]=get_time_us()-t0;

    t0=get_time_us();
    poly_vec_t M_mask;PQC_GenerateMask(k_sym_nvram,c_seed,ctr_local,R_dyn,&M_mask);
    poly_vec_t zmm,zu;pqzk_vec_sub(&resp_z,&M_mask,&zmm, PQ_ZK_M);
    for(int i=0;i<PQ_ZK_M*PQ_ZK_N;i++){int32_t v=zmm.coeffs[i];if(v>PQ_ZK_Q_VAL/2)v-=PQ_ZK_Q_VAL;zu.coeffs[i]=v;}
    norm_precheck(&zu,params,ov,un,l1);
    PQ_ZK_ErrorCode vrc=PQC_VerifyEngine(PQZK_MATRIX_A_SEED,pk_t,&W,&resp_z,c_seed,R_dyn,&M_mask,params);
    timings[6]=get_time_us()-t0;
    if(k_sym_out)pqzk_kdf(k_sym_before,d_seed,eid,16,k_sym_out);
    return vrc;}

static void make_sparse_ypub(const uint8_t seed[PQ_ZK_SEED_BYTES],double rho,poly_vec_t*out){
    PQC_RegenerateYpub(seed,out);
    for(int i=0;i<PQ_ZK_M*PQ_ZK_N;i++){uint8_t rb;pqzk_rand_bytes(&rb,1);if((double)rb/255.0>rho)out->coeffs[i]=0;}}

static void run_sparse_noise_attack_experiment(void){
    printf("\n=== Sparse Noise Attack ===\n");
    FILE*csv=fopen("sparse_noise_attack_results.csv","w");if(!csv){perror("fopen");return;}
    fprintf(csv,"rho,detection_rate,false_reject_rate,avg_total_us\n");
    const char*nd="/tmp/pqzk_sparse";system("mkdir -p /tmp/pqzk_sparse");
    uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES];poly_vec_t sk_s;PQC_GenKeyPair(pk_t,&sk_s);
    uint8_t eid[16]={0},k_sym[32],k_tee[32],d_seed[32],R_bio[32],salt[32],cred_kyc[PQZK_MLDSA_SIG_BYTES];
    pqzk_rand_bytes(k_sym,32);pqzk_rand_bytes(k_tee,32);pqzk_rand_bytes(R_bio,32);
    pqzk_rand_bytes(salt,32);pqzk_rand_bytes(cred_kyc,64);pqzk_sha3_256(k_sym,32,d_seed);
    double rhos[]={0.0,0.05,0.10,0.25,0.50,0.75,0.90,1.0};int nr=(int)(sizeof(rhos)/sizeof(rhos[0]));
    beta_params_t params=PQZK_DEFAULT_BETA_PARAMS;
    for(int ri=0;ri<nr;ri++){
        double rho=rhos[ri];int trials=200,detected=0,accepted=0,false_rej=0;double sum_us=0.0;
        printf("  rho=%.2f ... ",rho);fflush(stdout);
        for(int r=0;r<trials;r++){
            uint64_t c0;pqzk_rand_bytes((uint8_t*)&c0,8);
            PQC_eUICC_Init(nd,eid,16,&sk_s,k_sym,32,c0,k_tee,32,salt,R_bio,cred_kyc,64);
            nvram_state_t st;nvram_read(nd,&st);uint64_t ctr=st.ctr_local;
            poly_vec_t Wp,Ws,W;uint8_t sy[PQ_ZK_SEED_BYTES],MW[PQ_ZK_MAC_BYTES];
            PQC_PreCompute(&Wp,sy);PQC_eUICC_Commit(nd,&Ws,MW);pqzk_vec_add(&Ws,&Wp,&W, PQ_ZK_K);
            uint8_t cs[PQ_ZK_SEED_BYTES];pqzk_rand_bytes(cs,PQ_ZK_SEED_BYTES);
            poly_t ca;PQC_GenChallenge(&W,cs,&ca);
            uint8_t cb[8];write_le64(cb,ctr);uint8_t Rd[32];
            pqzk_iov_t rv[]={{R_bio,32},{cb,8},{NULL,0}};pqzk_sha3_256_iov(rv,Rd);
            uint8_t tok[PQ_ZK_MAC_BYTES];build_auth_token(k_tee,&ca,ctr,Rd,tok);
            poly_vec_t zsm;
            if(PQC_ComputeZ_and_Mask(nd,&ca,cs,Rd,tok,&zsm)!=PQ_ZK_SUCCESS)continue;
            double t0=get_time_us();
            poly_vec_t ya,rz;PQC_RegenerateYpub(sy,&ya);PQC_LPA_Aggregate(&zsm,&ya,&rz);
            poly_vec_t Mm;PQC_GenerateMask(k_sym,cs,ctr,Rd,&Mm);
            poly_vec_t zmm,zu;pqzk_vec_sub(&rz,&Mm,&zmm, PQ_ZK_M);
            for(int i=0;i<PQ_ZK_M*PQ_ZK_N;i++){int32_t v=zmm.coeffs[i];if(v>PQ_ZK_Q_VAL/2)v-=PQ_ZK_Q_VAL;zu.coeffs[i]=v;}
            if (rho < 1.0) {
                for(int i=0;i<PQ_ZK_M*PQ_ZK_N;i++){
                    uint8_t rb; pqzk_rand_bytes(&rb,1);
                    if((double)rb/255.0>rho)zu.coeffs[i]=0;
                }
            }
            PQ_ZK_ErrorCode vr = PQC_VerifyEngine(PQZK_MATRIX_A_SEED,pk_t,&W,&rz,cs,Rd,&Mm,&params);
            if(vr==PQ_ZK_SUCCESS)accepted++; else false_rej++;

            int d1=0,d2=0,lh=0;
            int64_t actual_l1 = 0;
            for(int i=0;i<PQ_ZK_M*PQ_ZK_N;i++){int32_t v = zu.coeffs[i]; actual_l1 += (v < 0) ? -v : v;}
            if (actual_l1 < (int64_t)params.beta_l1) detected++;
            norm_precheck(&zu,&params,&d1,&d2,&lh);
            sum_us+=get_time_us()-t0;}
        double dr=(double)detected/trials,fr=(double)false_rej/trials,avg=sum_us/trials;
        fprintf(csv,"%.2f,%.6f,%.6f,%.2f\n",rho,dr,fr,avg);
        printf("detected=%.1f%% accepted=%.1f%% avg=%.1fus\n",dr*100,(double)accepted/trials*100,avg);}
    fclose(csv);system("rm -rf /tmp/pqzk_sparse");printf("-> sparse_noise_attack_results.csv\n");}

static void run_sliding_window_resync_experiment(void){
    printf("\n=== Sliding Window Resync ===\n");
    FILE*csv=fopen("sliding_window_resync_results.csv","w");if(!csv){perror("fopen");return;}
    fprintf(csv,"window_size,sync_depth,success_rate,avg_mac_us,avg_total_us\n");
    const char*nd="/tmp/pqzk_resync";system("mkdir -p /tmp/pqzk_resync");
    uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES];poly_vec_t sk_s;PQC_GenKeyPair(pk_t,&sk_s);
    uint8_t eid[16]={0},k_sym[32],k_tee[32],d_seed[32],R_bio[32],salt[32],cred_kyc[PQZK_MLDSA_SIG_BYTES];
    pqzk_rand_bytes(k_sym,32);pqzk_rand_bytes(k_tee,32);pqzk_rand_bytes(R_bio,32);
    pqzk_rand_bytes(salt,32);pqzk_rand_bytes(cred_kyc,64);pqzk_sha3_256(k_sym,32,d_seed);
    int ws[]={1,2,4,8,16,32},ds[]={0,1,2,4,8,16,32,64};
    int nw=(int)(sizeof(ws)/sizeof(ws[0])),nd2=(int)(sizeof(ds)/sizeof(ds[0]));
    beta_params_t params=PQZK_DEFAULT_BETA_PARAMS;
    for(int wi=0;wi<nw;wi++){
        int W=ws[wi];
        for(int di=0;di<nd2;di++){
            int D=ds[di];printf("  W=%d D=%d ... ",W,D);fflush(stdout);
            int trials=5,ok=0;double smac=0.0,stot=0.0;
            for(int r=0;r<trials;r++){
                uint64_t ctr0;pqzk_rand_bytes((uint8_t*)&ctr0,8);
                PQC_eUICC_Init(nd,eid,16,&sk_s,k_sym,32,ctr0,k_tee,32,salt,R_bio,cred_kyc,64);
                server_state_t srv;memset(&srv,0,sizeof(srv));
                memcpy(srv.eid,eid,16);
                memcpy(srv.k_sym,k_sym,32);
                memcpy(srv.d_seed,d_seed,32);
                srv.ctr_server=ctr0;
                uint8_t ck[32];memcpy(ck,k_sym,32);int dok=1;
                for(int d=0;d<D;d++){
                    double dt[7];uint8_t ke[32];uint64_t cs;
                    if(run_one_trial(nd,pk_t,ck,k_tee,d_seed,eid,R_bio,&params,dt,NULL,NULL,NULL,ke,&cs)!=PQ_ZK_SUCCESS){dok=0;break;}
                    memcpy(ck,ke,32);}
                if(!dok){smac+=0;stot+=0;continue;}
                nvram_state_t sn;nvram_read(nd,&sn);uint64_t ctr_now=sn.ctr_local;
                poly_vec_t Wp,Ws,W2;uint8_t sy[PQ_ZK_SEED_BYTES],MW[PQ_ZK_MAC_BYTES];
                PQC_PreCompute(&Wp,sy);PQC_eUICC_Commit(nd,&Ws,MW);pqzk_vec_add(&Ws,&Wp,&W2, PQ_ZK_K);
                double tm0=get_time_us();uint64_t cs2;uint8_t ks[32];
                PQ_ZK_ErrorCode src=PQC_Server_SlidingWindowSync(&srv,&Ws,MW,(uint32_t)W,&cs2,ks);
                double mac_us=get_time_us()-tm0;smac+=mac_us;
                if(src!=PQ_ZK_SUCCESS){stot+=mac_us;continue;}
                double tt0=get_time_us();
                uint8_t cs_buf[PQ_ZK_SEED_BYTES];pqzk_rand_bytes(cs_buf,PQ_ZK_SEED_BYTES);
                poly_t ca2;PQC_GenChallenge(&W2,cs_buf,&ca2);
                uint8_t cb[8];write_le64(cb,ctr_now);uint8_t Rd[32];
                pqzk_iov_t rv[]={{R_bio,32},{cb,8},{NULL,0}};pqzk_sha3_256_iov(rv,Rd);
                uint8_t tok[PQ_ZK_MAC_BYTES];build_auth_token(k_tee,&ca2,ctr_now,Rd,tok);
                poly_vec_t zsm;
                if(PQC_ComputeZ_and_Mask(nd,&ca2,cs_buf,Rd,tok,&zsm)==PQ_ZK_SUCCESS){
                    poly_vec_t yp,rz;PQC_RegenerateYpub(sy,&yp);PQC_LPA_Aggregate(&zsm,&yp,&rz);
                    poly_vec_t Mm;PQC_GenerateMask(ks,cs_buf,ctr_now,Rd,&Mm);
                    if(PQC_VerifyEngine(PQZK_MATRIX_A_SEED,pk_t,&W2,&rz,cs_buf,Rd,&Mm,&params)==PQ_ZK_SUCCESS){
                        ok++;PQC_Server_CommitSync(&srv,cs2,ks);}}
                stot+=get_time_us()-tt0+mac_us;}
            double sr=(double)ok/trials,am=smac/trials,at=stot/trials;
            fprintf(csv,"%d,%d,%.6f,%.2f,%.2f\n",W,D,sr,am,at);
            printf("ok=%.1f%% mac=%.1fus tot=%.1fus\n",sr*100,am,at);}}
    fclose(csv);system("rm -rf /tmp/pqzk_resync");printf("-> sliding_window_resync_results.csv\n");}

static void run_operator_switching_experiment(void){
    printf("\n=== Operator Switching ===\n");
    FILE*csv=fopen("operator_switching_results.csv","w");if(!csv){perror("fopen");return;}
    fprintf(csv,"trial,direction,switch_time_us,success\n");
    const char*nd="/tmp/pqzk_switch";system("mkdir -p /tmp/pqzk_switch");
    uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES];poly_vec_t sk_s;PQC_GenKeyPair(pk_t,&sk_s);
    uint8_t eid[16]={0},k_sym[32],k_tee[32],R_bio[32],salt[32],cred_kyc[PQZK_MLDSA_SIG_BYTES];
    pqzk_rand_bytes(k_sym,32);pqzk_rand_bytes(k_tee,32);pqzk_rand_bytes(R_bio,32);
    pqzk_rand_bytes(salt,32);
    uint8_t aid[PQZK_MNO_ID_BYTES],bid[PQZK_MNO_ID_BYTES];
    memset(aid,0,PQZK_MNO_ID_BYTES);memset(bid,0,PQZK_MNO_ID_BYTES);
    memcpy(aid,"MNO_A_001",9);memcpy(bid,"MNO_B_001",9);
    memset(cred_kyc, 0, PQZK_MLDSA_SIG_BYTES);
    size_t ck_len; PQZK_CredKYC_Issue(eid, aid, R_bio, cred_kyc, &ck_len);
    uint64_t ic;pqzk_rand_bytes((uint8_t*)&ic,8);
    PQC_eUICC_Init(nd,eid,16,&sk_s,k_sym,32,ic,k_tee,32,salt,R_bio,cred_kyc,ck_len);
    { nvram_state_t st; nvram_read(nd,&st); memcpy(st.R_bio,R_bio,32); memcpy(st.active_R_bio,R_bio,32); nvram_write_atomic(nd,&st); }
    int trials=20,sc=0,cur=0;
    for(int r=0;r<trials;r++){
        const uint8_t*fi=cur?bid:aid,*ti=cur?aid:bid;
        const char*dir=cur?"B->A":"A->B";
        printf("  Trial %d (%s) ... ",r+1,dir);fflush(stdout);
        double t0=get_time_us();int res=mode_switch(nd,ti,fi);double us=get_time_us()-t0;
        int ok=(res==0)?1:0;if(ok){sc++;cur=1-cur;}
        fprintf(csv,"%d,%s,%.2f,%d\n",r+1,dir,us,ok);
        printf("%.1fus %s\n",us,ok?"OK":"FAIL");}
    fclose(csv);system("rm -rf /tmp/pqzk_switch");
    printf("-> operator_switching_results.csv\n");
    printf("   Success: %.1f%%\n",(double)sc/trials*100);}

static void run_nvm_wear_experiment(void){
    printf("\n=== NVM Wear ===\n");
    FILE*csv=fopen("nvm_wear_results.csv","w");if(!csv){perror("fopen");return;}
    fprintf(csv,"operation,nvram_writes,total_time_us,bytes_written,success_count\n");
    const char*nd="/tmp/pqzk_nvm";system("mkdir -p /tmp/pqzk_nvm");
    uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES];poly_vec_t sk_s;PQC_GenKeyPair(pk_t,&sk_s);
    uint8_t eid[16]={0},k_sym[32],k_tee[32],d_seed[32],R_bio[32],salt[32],cred_kyc[PQZK_MLDSA_SIG_BYTES];
    pqzk_rand_bytes(k_sym,32);pqzk_rand_bytes(k_tee,32);pqzk_rand_bytes(R_bio,32);
    pqzk_rand_bytes(salt,32);pqzk_sha3_256(k_sym,32,d_seed);
    beta_params_t params=PQZK_DEFAULT_BETA_PARAMS;
    uint64_t ctr0=100000ULL;
    PQC_eUICC_Init(nd,eid,16,&sk_s,k_sym,32,ctr0,k_tee,32,salt,R_bio,cred_kyc,64);
    int at=50,as=0;double atime=0.0;
    nvram_reset_write_count();
    for(int r=0;r<at;r++){
        double t[7];uint8_t ke[32];uint64_t cs;
        double t0=get_time_us();
        PQ_ZK_ErrorCode rc=run_one_trial(nd,pk_t,k_sym,k_tee,d_seed,eid,R_bio,&params,t,NULL,NULL,NULL,ke,&cs);
        atime+=get_time_us()-t0;
        if(rc==PQ_ZK_SUCCESS){as++;memcpy(k_sym,ke,32);}}
    uint64_t aw=nvram_get_write_count();
    uint64_t ab=nvram_get_byte_count();
    fprintf(csv,"authentication,%lu,%.2f,%lu,%d\n",(unsigned long)aw,atime,(unsigned long)ab,as);
    printf("  Auth: %lu writes %.1fms %d/%d ok\n",(unsigned long)aw,atime/1000.0,as,at);
    fprintf(csv,"total,%lu,%.2f,%lu,%d\n",(unsigned long)aw,atime,(unsigned long)ab,as);
    {
        FILE *lf = fopen("nvm_latency_results.csv", "w");
        fprintf(lf, "trial,latency_us\n");
        nvram_state_t lt_st; nvram_read(nd, &lt_st);
        int lat_trials = 1000;
        for (int i = 0; i < lat_trials; i++) {
            lt_st.ctr_local++;
            double t0 = get_time_us();
            nvram_write_atomic(nd, &lt_st);
            double lat = get_time_us() - t0;
            fprintf(lf, "%d,%.2f\n", i, lat);
        }
        fclose(lf);
        printf("-> nvm_latency_results.csv\n");
    }
    fclose(csv);system("rm -rf /tmp/pqzk_nvm");printf("-> nvm_wear_results.csv\n");}

static void run_phase_timing_experiment(void){
    printf("\n=== Per-Phase Timing ===\n");
    FILE*csv=fopen("phase_timing_results.csv","w");if(!csv){perror("fopen");return;}
    fprintf(csv,"trial,lpa_precompute_us,euicc_commit_us,challenge_gen_us,tee_authtoken_us,euicc_mask_us,lpa_aggregate_us,server_verify_us,total_us,euicc_total_us,lpa_total_us,tee_total_us,server_total_us\n");
    const char*nd="/tmp/pqzk_timing";system("mkdir -p /tmp/pqzk_timing");
    uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES];poly_vec_t sk_s;PQC_GenKeyPair(pk_t,&sk_s);
    uint8_t eid[16]={0},k_sym[32],k_tee[32],d_seed[32],R_bio[32],salt[32],cred_kyc[PQZK_MLDSA_SIG_BYTES];
    pqzk_rand_bytes(k_sym,32);pqzk_rand_bytes(k_tee,32);pqzk_rand_bytes(R_bio,32);
    pqzk_rand_bytes(salt,32);pqzk_rand_bytes(cred_kyc,64);pqzk_sha3_256(k_sym,32,d_seed);
    beta_params_t params=PQZK_DEFAULT_BETA_PARAMS;
    int trials=500,valid=0;double sum[7]={0},ssq[7]={0},mn[7],mx[7];
    for(int i=0;i<7;i++){mn[i]=1e18;mx[i]=0;}
    for(int r=0;r<trials;r++){
        uint64_t c;pqzk_rand_bytes((uint8_t*)&c,8);
        PQC_eUICC_Init(nd,eid,16,&sk_s,k_sym,32,c,k_tee,32,salt,R_bio,cred_kyc,64);
        double t[7];uint8_t ke[32];uint64_t cs;
        if(run_one_trial(nd,pk_t,k_sym,k_tee,d_seed,eid,R_bio,&params,t,NULL,NULL,NULL,ke,&cs)!=PQ_ZK_SUCCESS)continue;
        valid++;double tot=0;
        for(int i=0;i<7;i++){sum[i]+=t[i];ssq[i]+=t[i]*t[i];if(t[i]<mn[i])mn[i]=t[i];if(t[i]>mx[i])mx[i]=t[i];tot+=t[i];}
        fprintf(csv,"%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f\n",r+1,t[0],t[1],t[2],t[3],t[4],t[5],t[6],tot,t[1]+t[4],t[0]+t[5],t[3],t[6]);
        if((r+1)%100==0)printf("  %d/%d\n",r+1,trials);}
    const char*ns[]={"LPA PreCompute","eUICC Commit","Challenge Gen","TEE AuthToken","eUICC Mask","LPA Aggregate","Server Verify"};
    double grand=0;printf("\n  Phase Timing valid=%d/%d:\n",valid,trials);
    for(int i=0;i<7;i++){double m=valid?sum[i]/valid:0,v=valid?ssq[i]/valid-m*m:0;printf("  %-20s %.1f+/-%.1f us\n",ns[i],m,v>0?sqrt(v):0);grand+=m;}
    printf("  Total: %.1f us\n",grand);
    fclose(csv);system("rm -rf /tmp/pqzk_timing");printf("-> phase_timing_results.csv\n");}

static void run_memory_experiment(void){
    printf("\n=== Memory ===\n");
    FILE*csv=fopen("memory_usage_results.csv","w");if(!csv){perror("fopen");return;}
    fprintf(csv,"phase,rss_before_kb,rss_after_kb,delta_kb,peak_kb\n");
    const char*nd="/tmp/pqzk_mem";system("mkdir -p /tmp/pqzk_mem");
    uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES];poly_vec_t sk_s;PQC_GenKeyPair(pk_t,&sk_s);
    uint8_t eid[16]={0},k_sym[32],k_tee[32],d_seed[32],R_bio[32],salt[32],cred_kyc[PQZK_MLDSA_SIG_BYTES];
    pqzk_rand_bytes(k_sym,32);pqzk_rand_bytes(k_tee,32);pqzk_rand_bytes(R_bio,32);
    pqzk_rand_bytes(salt,32);pqzk_rand_bytes(cred_kyc,64);pqzk_sha3_256(k_sym,32,d_seed);
    beta_params_t params=PQZK_DEFAULT_BETA_PARAMS;
    int trials=20;long peak=0;
    const char*pn[]={"LPA_PreCompute","eUICC_Commit","Challenge_Gen","TEE_AuthToken","eUICC_Mask","LPA_Aggregate","Server_Verify"};
    long rb[7][20],ra[7][20];
    for(int r=0;r<trials;r++){
        uint64_t c;pqzk_rand_bytes((uint8_t*)&c,8);
        PQC_eUICC_Init(nd,eid,16,&sk_s,k_sym,32,c,k_tee,32,salt,R_bio,cred_kyc,64);
        nvram_state_t st;nvram_read(nd,&st);uint64_t ctr=st.ctr_local;
        poly_vec_t Wp,Ws,W;uint8_t sy[PQ_ZK_SEED_BYTES],MW[PQ_ZK_MAC_BYTES];
        usleep(1000); rb[0][r]=get_rss_kb(); usleep(1000); PQC_PreCompute(&Wp,sy); usleep(1000); ra[0][r]=get_rss_kb(); usleep(1000);
        usleep(1000); rb[1][r]=get_rss_kb(); usleep(1000); PQC_eUICC_Commit(nd,&Ws,MW); usleep(1000); ra[1][r]=get_rss_kb(); usleep(1000);
        pqzk_vec_add(&Ws,&Wp,&W, PQ_ZK_K);
        uint8_t cs[PQ_ZK_SEED_BYTES];pqzk_rand_bytes(cs,PQ_ZK_SEED_BYTES);poly_t ca;
        usleep(1000); rb[2][r]=get_rss_kb(); usleep(1000); PQC_GenChallenge(&W,cs,&ca); usleep(1000); ra[2][r]=get_rss_kb(); usleep(1000);
        uint8_t cb[8];write_le64(cb,ctr);uint8_t Rd[32];
        pqzk_iov_t rv[]={{R_bio,32},{cb,8},{NULL,0}};pqzk_sha3_256_iov(rv,Rd);
        uint8_t tok[PQ_ZK_MAC_BYTES];
        usleep(1000); rb[3][r]=get_rss_kb(); usleep(1000); build_auth_token(k_tee,&ca,ctr,Rd,tok); usleep(1000); ra[3][r]=get_rss_kb(); usleep(1000);
        poly_vec_t zsm;
        usleep(1000); rb[4][r]=get_rss_kb(); usleep(1000); PQC_ComputeZ_and_Mask(nd,&ca,cs,Rd,tok,&zsm); usleep(1000); ra[4][r]=get_rss_kb(); usleep(1000);
        poly_vec_t yp,rz;PQC_RegenerateYpub(sy,&yp);
        usleep(1000); rb[5][r]=get_rss_kb(); usleep(1000); PQC_LPA_Aggregate(&zsm,&yp,&rz); usleep(1000); ra[5][r]=get_rss_kb(); usleep(1000);
        poly_vec_t Mm;PQC_GenerateMask(k_sym,cs,ctr,Rd,&Mm);
        usleep(1000); rb[6][r]=get_rss_kb(); usleep(1000); PQC_VerifyEngine(PQZK_MATRIX_A_SEED,pk_t,&W,&rz,cs,Rd,&Mm,&params); usleep(1000); ra[6][r]=get_rss_kb(); usleep(1000);
        if(ra[6][r]>peak)peak=ra[6][r];}
    for(int i=0;i<7;i++){long sb=0,sa=0;for(int r=0;r<trials;r++){sb+=rb[i][r];sa+=ra[i][r];}long ab=sb/trials,aa=sa/trials;fprintf(csv,"%s,%ld,%ld,%ld,%ld\n",pn[i],ab,aa,aa-ab,peak);}
    long lpa_rss=0, euicc_rss=0, server_rss=0;
    for(int r=0;r<trials;r++){
        long lpa_max=0; lpa_max=ra[0][r]>lpa_max?ra[0][r]:lpa_max; lpa_max=ra[2][r]>lpa_max?ra[2][r]:lpa_max; lpa_max=ra[5][r]>lpa_max?ra[5][r]:lpa_max; lpa_rss+=lpa_max;
        long euicc_max=0; euicc_max=ra[1][r]>euicc_max?ra[1][r]:euicc_max; euicc_max=ra[3][r]>euicc_max?ra[3][r]:euicc_max; euicc_max=ra[4][r]>euicc_max?ra[4][r]:euicc_max; euicc_rss+=euicc_max;
        server_rss+=ra[6][r];}
    lpa_rss/=trials; euicc_rss/=trials; server_rss/=trials;
    fprintf(csv,"\ncomponent,avg_rss_kb\n"); fprintf(csv,"LPA,%ld\n",lpa_rss); fprintf(csv,"eUICC,%ld\n",euicc_rss); fprintf(csv,"Server,%ld\n",server_rss);
    printf("  Peak RSS: %ld KB | nvram_state_t=%zuB poly_vec_t=%zuB\n",peak,sizeof(nvram_state_t),sizeof(poly_vec_t));
    printf("  Component Memory Usage:\n"); printf("    LPA: %ld KB\n",lpa_rss); printf("    eUICC: %ld KB\n",euicc_rss); printf("    Server: %ld KB\n",server_rss);
    fclose(csv);system("rm -rf /tmp/pqzk_mem");printf("-> memory_usage_results.csv\n");
}

int main(int argc,char*argv[]){
    const char* only = NULL;
    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"--only") && i+1<argc){ only=argv[++i]; }
    }
    printf("============================================\n");
    printf("  PQ-ZK-eSIM Experiments v5.1\n");
    printf("============================================\n");
    int run_all = (only == NULL);
    if(run_all || (only && !strcmp(only,"nvm")))     run_nvm_wear_experiment();
    if(run_all || (only && !strcmp(only,"sparse")))  run_sparse_noise_attack_experiment();
    if(run_all || (only && !strcmp(only,"sliding"))) run_sliding_window_resync_experiment();
    if(run_all || (only && !strcmp(only,"phase")))   run_phase_timing_experiment();
    if(run_all || (only && !strcmp(only,"memory")))  run_memory_experiment();
    printf("\nAll done.\n");
    return 0;}
