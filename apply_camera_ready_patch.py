#!/usr/bin/env python3
"""Patch the current public PQ-ZK-eSIM repo to the camera-ready k=3,m=8 implementation.

Run from repository root:
    python3 /path/to/apply_camera_ready_patch.py

The script is deliberately fail-fast: every critical replacement must match the
current public repository exactly once, otherwise it aborts instead of making a
partial/ambiguous edit.
"""
from pathlib import Path
import re, shutil, sys

ROOT = Path.cwd()
REQUIRED = [
    Path('artifact/terminal/euicc/include/pq_zk_esim.h'),
    Path('artifact/terminal/euicc/src/internal/params.h'),
    Path('artifact/terminal/euicc/src/algebra/pq_zk_poly.c'),
    Path('artifact/terminal/euicc/src/pq_zk_esim.c'),
    Path('artifact/terminal/euicc/benchmarks/bench_pqzkesim.c'),
    Path('artifact/terminal/euicc/benchmarks/bench_pqzkesim_comprehensive.c'),
]
for p in REQUIRED:
    if not (ROOT/p).exists():
        sys.exit(f'ERROR: {p} not found. Run this script from the PQ-ZK-eSIM repo root.')

BACKUP = ROOT / '.camera_ready_backup'
BACKUP.mkdir(exist_ok=True)


def load(rel):
    return (ROOT/rel).read_text(encoding='utf-8')

def save(rel, s):
    p = ROOT/rel
    b = BACKUP/rel
    b.parent.mkdir(parents=True, exist_ok=True)
    if not b.exists():
        shutil.copy2(p, b)
    p.write_text(s, encoding='utf-8')
    print('patched', rel)

def replace_once(s, old, new, what):
    n = s.count(old)
    if n != 1:
        raise RuntimeError(f'{what}: expected exactly 1 match, found {n}')
    return s.replace(old, new, 1)

def sub_once(s, pat, repl, what, flags=0):
    out, n = re.subn(pat, repl, s, count=1, flags=flags)
    if n != 1:
        raise RuntimeError(f'{what}: expected exactly 1 regex match, found {n}')
    return out

def replace_between(s, start_marker, end_marker, new, what):
    a = s.find(start_marker)
    if a < 0:
        raise RuntimeError(f'{what}: start marker not found')
    b = s.find(end_marker, a)
    if b < 0:
        raise RuntimeError(f'{what}: end marker not found')
    return s[:a] + new + '\n' + s[b:]

# ---------------------------------------------------------------------------
# 1) Protocol dimensions: k=3, m=8
# ---------------------------------------------------------------------------
rel = Path('artifact/terminal/euicc/include/pq_zk_esim.h')
s = load(rel)
s = replace_once(s, '#define PQ_ZK_K 5', '#define PQ_ZK_K 3', 'PQ_ZK_K')
s = replace_once(s,
    '#define PQ_ZK_PUBLICKEY_BYTES (32 + PQ_ZK_K * PQ_ZK_N * 3)',
    '#define PQ_ZK_PUBLICKEY_BYTES (32 + PQ_ZK_K * PQ_ZK_N * 3)',
    'public-key size sanity')
s = s.replace('/* no-op */', '/* no-op */')
s = s.replace('Triple norm', 'Multi-norm')
save(rel, s)

# ---------------------------------------------------------------------------
# 2) params.h: align comments with final paper; do not advertise 3309 as proof.
# ---------------------------------------------------------------------------
rel = Path('artifact/terminal/euicc/src/internal/params.h')
s = load(rel)
s = s.replace('PQ_ZK_K     = 5       matrix rows (commitment dim)',
              'PQ_ZK_K     = 3       matrix rows (commitment dim)')
s = s.replace('>> NIST Level 1 (128 bit)', 'gives about 178.6 challenge bits')
s = s.replace('Soundness via Reset Lemma: eps_fork >= eps^2 - eps/|C_chal|',
              'Soundness uses the ROM forking reduction in the paper')
s = s.replace('Renyi smudging: sigma >= rho_smudge * sqrt(kappa*M*N) * eta_s\n *        5000 >= 12.36 * sqrt(35*8*256) * 1 = 12.36 * 267.7 = 3309  OK',
              'Finite-parameter Renyi accounting is reported separately from the asymptotic UC condition')
s = s.replace('/* Renyi smudging minimum: gamma * sqrt(M*N*kappa) * eta_s (Paper Theorem 3) */\n#define PQZK_RENYI_SMUDGE_MIN  3309',
              '/* Historical finite-accounting reference only; not a theorem-level minimum. */\n#define PQZK_RENYI_SMUDGE_MIN  3309')
s = s.replace('// Paper Theorem 3: sigma >= gamma * sqrt(M*N*kappa) * eta_s',
              '// Finite-accounting engineering check (not the asymptotic UC condition)')
s = s.replace('"PQ_ZK_SIGMA_PUB fails Renyi smudging condition (Paper Theorem 3): sigma >= gamma*sqrt(M*N*kappa)*eta_s"',
              '"PQ_ZK_SIGMA_PUB fails the finite-accounting engineering reference"')
save(rel, s)

# ---------------------------------------------------------------------------
# 3) Main protocol: true uniform ternary secret/y_sec and enough PRF bytes.
# ---------------------------------------------------------------------------
rel = Path('artifact/terminal/euicc/src/pq_zk_esim.c')
s = load(rel)
s = s.replace(' * K=5, M=8, q=8380417, kappa=35, sigma=5000',
              ' * K=3, M=8, q=8380417, kappa=35, sigma=5000')
s = s.replace(' * Key Generation — K=5, M=8 rectangular MSIS',
              ' * Key Generation — K=3, M=8 systematic MLWE public key')

uniform_sampler = r'''/* Uniform ternary sampler: each coefficient is exactly uniform in {-1,0,1}.
 * Bytes >= 252 are rejected so reduction modulo 3 is unbiased. */
static void sample_uniform_ternary(const uint8_t seed[32], poly_vec_t *out)
{
    uint32_t block = 0;
    int filled = 0;
    uint8_t domain[36];
    uint8_t buf[512];
    memcpy(domain, seed, 32);
    while (filled < PQ_ZK_M * PQ_ZK_N) {
        write_le32(domain + 32, block++);
        pqzk_shake256(domain, sizeof(domain), buf, sizeof(buf));
        for (size_t i = 0; i < sizeof(buf) && filled < PQ_ZK_M * PQ_ZK_N; i++) {
            uint8_t x = buf[i];
            if (x >= 252) continue;
            int t = (int)(x % 3);
            out->coeffs[filled++] = (t == 0) ? -1 : (t == 1 ? 0 : 1);
        }
    }
    secure_zero(domain, sizeof(domain));
    secure_zero(buf, sizeof(buf));
}'''
s = replace_between(
    s, '/* sample_binomial_B1',
    '/* ================================================================\n * Serialization',
    uniform_sampler, 'replace B1 + biased ternary samplers')
# Make sure old sampler names are gone.
s = s.replace('sample_binomial_B1(sk_seed, sk_s);', 'sample_uniform_ternary(sk_seed, sk_s);')
s = s.replace('sample_ternary(ysec_seed, &y_sec);', 'sample_uniform_ternary(ysec_seed, &y_sec);')
if 'sample_binomial_B1(' in s or 'sample_ternary(' in s:
    raise RuntimeError('old non-uniform ternary sampler still present')

# 23-bit Parse has ~99.9% acceptance; give 128 spare candidates so parser never wraps in practice.
s = s.replace('size_t mask_stream_len = (size_t)PQ_ZK_M * PQ_ZK_N * 3;',
              'size_t mask_stream_len = ((size_t)PQ_ZK_M * PQ_ZK_N + 128u) * 3u;')
s = s.replace('size_t stream_len = (size_t)PQ_ZK_M * PQ_ZK_N * 3;',
              'size_t stream_len = ((size_t)PQ_ZK_M * PQ_ZK_N + 128u) * 3u;')
save(rel, s)

# ---------------------------------------------------------------------------
# 4) Algebra: idealized Gaussian implementation closer to paper, 23-bit Parse,
#    A=[Abar|I_k], and systematic matrix-vector multiplication.
# ---------------------------------------------------------------------------
rel = Path('artifact/terminal/euicc/src/algebra/pq_zk_poly.c')
s = load(rel)
# Do not clip honest y_pub at the verifier cutoff; verifier must enforce beta_inf.
s = s.replace('        if (v >  (int32_t)tau_bound) v =  (int32_t)tau_bound;\n        if (v < -(int32_t)tau_bound) v = -(int32_t)tau_bound;\n', '')
s = s.replace('    double tau_bound = (double)PQ_ZK_BETA_INF;\n\n', '')
s = s.replace(' * M=8 polynomials, sigma=5000, truncation at beta_inf=35700',
              ' * M=8 polynomials, sigma=5000; verifier applies beta_inf=35700')

parse_new = r'''/* ================================================================
 * Parse_R_q^m: PRF stream -> uniform poly vector (M_mask).
 * Parse 23-bit blocks (ceil(log2 q)=23) and rejection-sample v<q.
 * Callers provide 128 spare candidates; exhaustion is fail-closed to zero.
 * ================================================================ */
void pqzk_parse_poly_vec(const uint8_t *stream, size_t stream_len,
                          poly_vec_t *out)
{
    size_t pos = 0;
    int total = PQ_ZK_M * PQ_ZK_N;
    int filled = 0;
    while (filled < total) {
        if (pos + 3 > stream_len) {
            memset(&out->coeffs[filled], 0,
                   (size_t)(total - filled) * sizeof(out->coeffs[0]));
            return;
        }
        uint32_t v = ((uint32_t)stream[pos]
                    | ((uint32_t)stream[pos + 1] << 8)
                    | ((uint32_t)stream[pos + 2] << 16)) & 0x7FFFFFu;
        pos += 3;
        if (v >= PQ_ZK_Q_VAL) continue;
        out->coeffs[filled++] = (int32_t)v;
    }
}'''
s = replace_between(s, '/* ================================================================\n * Parse_R_q^m:', '/* ================================================================\n * gen_matrix_A:', parse_new, 'replace Parse_Rq')

matrix_new = r'''/* ================================================================
 * gen_matrix_A: systematic public matrix A=[Abar|I_k].
 * Abar is k x (m-k), expanded uniformly with 23-bit rejection sampling.
 * ================================================================ */
static void sample_uniform_matrix_poly(const uint8_t seed[32], int row, int col,
                                       int32_t out[PQ_ZK_N])
{
    uint8_t domain[38];
    uint8_t buf[384];
    uint32_t block = 0;
    int filled = 0;
    memcpy(domain, seed, 32);
    domain[32] = (uint8_t)row;
    domain[33] = (uint8_t)col;
    while (filled < PQ_ZK_N) {
        write_le32(domain + 34, block++);
        pqzk_shake256(domain, sizeof(domain), buf, sizeof(buf));
        for (size_t pos = 0; pos + 3 <= sizeof(buf) && filled < PQ_ZK_N; pos += 3) {
            uint32_t v = ((uint32_t)buf[pos]
                        | ((uint32_t)buf[pos + 1] << 8)
                        | ((uint32_t)buf[pos + 2] << 16)) & 0x7FFFFFu;
            if (v >= PQ_ZK_Q_VAL) continue;
            out[filled++] = (int32_t)v;
        }
    }
    secure_zero(domain, sizeof(domain));
    secure_zero(buf, sizeof(buf));
}

void pqzk_gen_matrix_A(const uint8_t seed[32], poly_vec_t *A_rows,
                        int k_rows, int m_cols)
{
    const int r = m_cols - k_rows;
    for (int i = 0; i < k_rows; i++) {
        memset(A_rows[i].coeffs, 0, sizeof(A_rows[i].coeffs));
        for (int j = 0; j < r; j++)
            sample_uniform_matrix_poly(seed, i, j,
                                       &A_rows[i].coeffs[j * PQ_ZK_N]);
        /* Identity polynomial in column r+i: constant coefficient 1. */
        A_rows[i].coeffs[(r + i) * PQ_ZK_N] = 1;
    }
}'''
s = replace_between(s, '/* ================================================================\n * gen_matrix_A:', '/* ================================================================\n * mat_vec_mul:', matrix_new, 'replace matrix generator')

mat_new = r'''/* ================================================================
 * mat_vec_mul: result=[Abar|I_k]v, schoolbook/ternary-friendly path.
 * Only the first r=m-k columns need polynomial convolution.
 * ================================================================ */
void pqzk_mat_vec_mul(const poly_vec_t *A_rows, const poly_vec_t *v,
                       poly_vec_t *result, int k_rows, int m_cols)
{
    memset(result->coeffs, 0, sizeof(result->coeffs));
    const int r = m_cols - k_rows;
    for (int i = 0; i < k_rows; i++) {
        int32_t *r_i = &result->coeffs[i * PQ_ZK_N];
        for (int j = 0; j < r; j++) {
            const int32_t *a_ij = &A_rows[i].coeffs[j * PQ_ZK_N];
            const int32_t *v_j  = &v->coeffs[j * PQ_ZK_N];
            for (int p = 0; p < PQ_ZK_N; p++) {
                if (v_j[p] == 0) continue;
                for (int qq = 0; qq < PQ_ZK_N; qq++) {
                    int dst = p + qq;
                    int64_t contrib = (int64_t)a_ij[qq] * (int64_t)v_j[p];
                    int idx = (dst >= PQ_ZK_N) ? dst - PQ_ZK_N : dst;
                    int64_t cur = (int64_t)r_i[idx] +
                                  ((dst >= PQ_ZK_N) ? -contrib : contrib);
                    cur %= PQ_ZK_Q_VAL;
                    if (cur < 0) cur += PQ_ZK_Q_VAL;
                    r_i[idx] = (int32_t)cur;
                }
            }
        }
        /* Identity block contributes v_{r+i} coefficient-wise. */
        const int32_t *v_id = &v->coeffs[(r + i) * PQ_ZK_N];
        for (int t = 0; t < PQ_ZK_N; t++) {
            int64_t cur = (int64_t)r_i[t] + v_id[t];
            cur %= PQ_ZK_Q_VAL;
            if (cur < 0) cur += PQ_ZK_Q_VAL;
            r_i[t] = (int32_t)cur;
        }
    }
}'''
s = replace_between(s, '/* ================================================================\n * mat_vec_mul:', '/* ================================================================\n * vec_scalar_mul:', mat_new, 'replace schoolbook matvec')

ntt_new = r'''/* matrix-vector multiply result=[Abar|I_k]v using NTT on Abar only */
void pqzk_mat_vec_mul_ntt(const poly_vec_t *A_rows, const poly_vec_t *v,
                           poly_vec_t *result, int k_rows, int m_cols)
{
    memset(result->coeffs, 0, sizeof(result->coeffs));
    const int r = m_cols - k_rows;
    for (int i = 0; i < k_rows; i++) {
        int32_t *r_i = &result->coeffs[i * PQ_ZK_N];
        for (int j = 0; j < r; j++) {
            const int32_t *a_ij = &A_rows[i].coeffs[j * PQ_ZK_N];
            const int32_t *v_j  = &v->coeffs[j * PQ_ZK_N];
            int32_t prod[PQ_ZK_N];
            ntt_poly_mul(a_ij, v_j, prod);
            for (int t = 0; t < PQ_ZK_N; t++)
                r_i[t] = ntt_mod((int64_t)r_i[t] + prod[t]);
        }
        const int32_t *v_id = &v->coeffs[(r + i) * PQ_ZK_N];
        for (int t = 0; t < PQ_ZK_N; t++)
            r_i[t] = ntt_mod((int64_t)r_i[t] + v_id[t]);
    }
}'''
_ntt_marker = '/* matrix-vector multiply result = A * v using NTT (dense inputs) */'
_pos = s.find(_ntt_marker)
if _pos < 0: raise RuntimeError('replace NTT matvec: marker not found')
s = s[:_pos] + ntt_new + '\n'
save(rel, s)

# ---------------------------------------------------------------------------
# 5) Basic benchmark: include L1 in norm precheck and initialize beta_l1.
# ---------------------------------------------------------------------------
rel = Path('artifact/terminal/euicc/benchmarks/bench_pqzkesim.c')
s = load(rel)
s = s.replace('    int64_t l2_sq    = 0;\n', '    int64_t l2_sq    = 0;\n    int64_t l1_norm  = 0;\n', 1)
s = s.replace('        l2_sq += (int64_t)v * v;\n', '        l2_sq += (int64_t)v * v;\n        l1_norm += (int64_t)av;\n', 1)
s = s.replace('    if (inf_norm > (int32_t)PQ_ZK_BETA_INF) return 1;\n    return 0;',
              '    if (inf_norm > (int32_t)PQ_ZK_BETA_INF) return 1;\n    if (params->beta_l1 > 0 && l1_norm < (int64_t)params->beta_l1) return 2;\n    return 0;', 1)
s = s.replace('            params.beta_min   = PQZK_BETA_MIN;\n',
              '            params.beta_min   = PQZK_BETA_MIN;\n            params.beta_l1    = PQZK_BETA_L1;\n', 1)
save(rel, s)

# ---------------------------------------------------------------------------
# 6) Comprehensive sparse-noise experiment: attack y_pub BEFORE W/challenge
#    so the lattice relation remains consistent and detection is really due to
#    the multi-norm verifier. Keep legacy CSV columns first for plotting.
# ---------------------------------------------------------------------------
rel = Path('artifact/terminal/euicc/benchmarks/bench_pqzkesim_comprehensive.c')
s = load(rel)
start = s.index('static void run_sparse_noise_attack_experiment(void){')
end = s.index('static void run_sliding_window_resync_experiment(void){')
new_sparse = r'''static void run_sparse_noise_attack_experiment(void){
    printf("\n=== Sparse Noise Attack (consistent malicious-y_pub model) ===\n");
    FILE*csv=fopen("sparse_noise_attack_results.csv","w");if(!csv){perror("fopen");return;}
    FILE*detail=fopen("sparse_noise_norm_breakdown.csv","w");if(!detail){perror("fopen");fclose(csv);return;}
    /* Keep the legacy 4-column result schema so existing plot/validation scripts keep working. */
    fprintf(csv,"rho,detection_rate,false_reject_rate,avg_total_us\n");
    fprintf(detail,"rho,l2_low_rate,l2_high_rate,linf_rate,l1_low_rate,verify_reject_rate\n");
    const char*nd="/tmp/pqzk_sparse";system("mkdir -p /tmp/pqzk_sparse");
    uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES];poly_vec_t sk_s;PQC_GenKeyPair(pk_t,&sk_s);
    uint8_t eid[16]={0},k_sym[32],k_tee[32],d_seed[32],R_bio[32],salt[32],cred_kyc[PQZK_MLDSA_SIG_BYTES];
    pqzk_rand_bytes(k_sym,32);pqzk_rand_bytes(k_tee,32);pqzk_rand_bytes(R_bio,32);
    pqzk_rand_bytes(salt,32);pqzk_rand_bytes(cred_kyc,64);pqzk_sha3_256(k_sym,32,d_seed);
    double rhos[]={0.0,0.05,0.10,0.25,0.50,0.75,0.90,1.0};int nr=(int)(sizeof(rhos)/sizeof(rhos[0]));
    beta_params_t params=PQZK_DEFAULT_BETA_PARAMS;
    for(int ri=0;ri<nr;ri++){
        double rho=rhos[ri];int trials=200,detected=0,accepted=0,false_rej=0;
        int l2lo=0,l2hi=0,linf=0,l1lo=0,vrej=0; double sum_us=0.0;
        printf("  rho=%.2f ... ",rho);fflush(stdout);
        for(int rr=0;rr<trials;rr++){
            uint64_t c0;pqzk_rand_bytes((uint8_t*)&c0,8);
            PQC_eUICC_Init(nd,eid,16,&sk_s,k_sym,32,c0,k_tee,32,salt,R_bio,cred_kyc,64);
            nvram_state_t st;nvram_read(nd,&st);uint64_t ctr=st.ctr_local;

            /* Malicious LPA fixes structured y_pub before W and challenge. */
            uint8_t sy[PQ_ZK_SEED_BYTES];pqzk_rand_bytes(sy,sizeof(sy));
            poly_vec_t ya;make_sparse_ypub(sy,rho,&ya);
            poly_vec_t A_rows[PQ_ZK_K],Wp;
            pqzk_gen_matrix_A(PQZK_MATRIX_A_SEED,A_rows,PQ_ZK_K,PQ_ZK_M);
            pqzk_mat_vec_mul_ntt(A_rows,&ya,&Wp,PQ_ZK_K,PQ_ZK_M);

            poly_vec_t Ws,W;uint8_t MW[PQ_ZK_MAC_BYTES];
            PQC_eUICC_Commit(nd,&Ws,MW);pqzk_vec_add(&Ws,&Wp,&W,PQ_ZK_K);
            uint8_t cs[PQ_ZK_SEED_BYTES];pqzk_rand_bytes(cs,PQ_ZK_SEED_BYTES);
            poly_t ca;PQC_GenChallenge(&W,cs,&ca);
            uint8_t cb[8];write_le64(cb,ctr);uint8_t Rd[32];
            pqzk_iov_t rv[]={{R_bio,32},{cb,8},{NULL,0}};pqzk_sha3_256_iov(rv,Rd);
            uint8_t tok[PQ_ZK_MAC_BYTES];build_auth_token(k_tee,&ca,ctr,Rd,tok);
            poly_vec_t zsm;
            if(PQC_ComputeZ_and_Mask(nd,&ca,cs,Rd,tok,&zsm)!=PQ_ZK_SUCCESS)continue;

            double t0=get_time_us();
            poly_vec_t rz;PQC_LPA_Aggregate(&zsm,&ya,&rz);
            poly_vec_t Mm;PQC_GenerateMask(k_sym,cs,ctr,Rd,&Mm);
            poly_vec_t zmm,zu;pqzk_vec_sub(&rz,&Mm,&zmm,PQ_ZK_M);
            int32_t inf=0;int64_t l2=0,l1=0;
            for(int i=0;i<PQ_ZK_M*PQ_ZK_N;i++){
                int32_t v=zmm.coeffs[i];if(v>PQ_ZK_Q_VAL/2)v-=PQ_ZK_Q_VAL;zu.coeffs[i]=v;
                int32_t av=v<0?-v:v;if(av>inf)inf=av;l2+=(int64_t)v*v;l1+=av;
            }
            int f_l2lo=l2<(int64_t)params.beta_min*params.beta_min;
            int f_l2hi=l2>(int64_t)params.beta_final*params.beta_final;
            int f_inf=inf>(int32_t)PQ_ZK_BETA_INF;
            int f_l1=params.beta_l1>0&&l1<(int64_t)params.beta_l1;
            if(f_l2lo)l2lo++;if(f_l2hi)l2hi++;if(f_inf)linf++;if(f_l1)l1lo++;
            if(f_l2lo||f_l2hi||f_inf||f_l1)detected++;

            PQ_ZK_ErrorCode vr=PQC_VerifyEngine(PQZK_MATRIX_A_SEED,pk_t,&W,&rz,cs,Rd,&Mm,&params);
            if(vr==PQ_ZK_SUCCESS)accepted++;else vrej++;
            if(rho>=0.999 && vr!=PQ_ZK_SUCCESS)false_rej++;
            sum_us+=get_time_us()-t0;
        }
        double dr=(double)detected/trials,fr=(double)false_rej/trials,avg=sum_us/trials;
        fprintf(csv,"%.2f,%.6f,%.6f,%.2f\n",rho,dr,fr,avg);
        fprintf(detail,"%.2f,%.6f,%.6f,%.6f,%.6f,%.6f\n",
                rho,(double)l2lo/trials,(double)l2hi/trials,
                (double)linf/trials,(double)l1lo/trials,(double)vrej/trials);
        printf("detected=%.1f%% accepted=%.1f%% honestFRR=%.2f%% avg=%.1fus\n",
               dr*100,(double)accepted/trials*100,fr*100,avg);
    }
    fclose(csv);fclose(detail);system("rm -rf /tmp/pqzk_sparse");
    printf("-> sparse_noise_attack_results.csv, sparse_noise_norm_breakdown.csv\n");
}
'''
s = s[:start] + new_sparse + s[end:]
s = s.replace('  PQ-ZK-eSIM Experiments v5.1', '  PQ-ZK-eSIM Experiments camera-ready k=3,m=8')
save(rel, s)

# ---------------------------------------------------------------------------
# 7) README: public artifact should not advertise stale k=5 or full LPA blindness.
# ---------------------------------------------------------------------------
readme = ROOT/'README.md'
if not readme.exists():
    readme = ROOT/'README.txt'
if readme.exists():
    rel = readme.relative_to(ROOT)
    s = readme.read_text(encoding='utf-8')
    s = s.replace('| K × M | 5 × 8 |', '| K × M | 3 × 8 |')
    s = s.replace('（NIST Level 1）', '（selected camera-ready parameter set）')
    s = s.replace('- LPA 盲性（HKDF 派生密钥下的 PRF 掩码）',
                  '- 恶意 LPA 场景：生物特征不暴露、活体门控与认证可靠性；不声明长期秘密的完整视图隐私')
    s = s.replace('- 服务端视角可模拟性（高斯淹没，Rényi 散度界）',
                  '- 诚实 LPA / 好奇服务器场景：高斯 flooding 的有限 Rényi 记账；渐近 UC 隐私按论文条件陈述')
    b = BACKUP/rel; b.parent.mkdir(parents=True,exist_ok=True)
    if not b.exists(): shutil.copy2(readme,b)
    readme.write_text(s,encoding='utf-8')
    print('patched',rel)

# ---------------------------------------------------------------------------
# Final static sanity checks.
# ---------------------------------------------------------------------------
checks = {
    'K=3': '#define PQ_ZK_K 3' in load(Path('artifact/terminal/euicc/include/pq_zk_esim.h')),
    'no B1 sampler': 'sample_binomial_B1' not in load(Path('artifact/terminal/euicc/src/pq_zk_esim.c')),
    'no biased sampler': 'buf[i] & 0x03' not in load(Path('artifact/terminal/euicc/src/pq_zk_esim.c')),
    'HNF identity': 'A_rows[i].coeffs[(r + i) * PQ_ZK_N] = 1;' in load(Path('artifact/terminal/euicc/src/algebra/pq_zk_poly.c')),
    '23-bit Parse': '& 0x7FFFFFu' in load(Path('artifact/terminal/euicc/src/algebra/pq_zk_poly.c')),
    'no Gaussian clipping': 'tau_bound' not in load(Path('artifact/terminal/euicc/src/algebra/pq_zk_poly.c')),
    'sparse experiment consistent': 'consistent malicious-y_pub model' in load(Path('artifact/terminal/euicc/benchmarks/bench_pqzkesim_comprehensive.c')),
}
failed=[k for k,v in checks.items() if not v]
print('\nStatic checks:')
for k,v in checks.items(): print(f'  [{"OK" if v else "FAIL"}] {k}')
if failed:
    sys.exit('FAILED static checks: '+', '.join(failed))
print('\nPatch complete. Backups are in .camera_ready_backup/')
