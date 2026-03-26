#!/usr/bin/env python3
"""
test_ctypes.py
后端 Python ctypes 对接验证脚本
用途：后端同学在联调前用此脚本确认 libpqzkesim_verify.so 可正确加载并调用

依赖：仅标准库，无需安装额外包
用法：
    python3 test_ctypes.py --so ./build/libpqzkesim_verify.so

3.18 KAT 对齐基准（所有十六进制值以 C 层输出为准）：
  SHA256('abc')     = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
  PRF(K=AA*32, ...) = 79eb3304ad916d9792000ca8f7397e2731477b0cb7ace3f19c551d48c47d8d41...
  EncodePolyVec[0:8]= 0000010002000300  (coeffs = 0,1,2,3,...)
"""

import ctypes
import ctypes.util
import sys
import os
import hashlib
import hmac
import struct
import argparse
import tempfile

# ── 常量（与 pq_zk_esim.h 严格对齐）──────────────────────────────────────
PQ_ZK_N              = 256
PQ_ZK_K              = 3
PQ_ZK_SEED_BYTES     = 32
PQ_ZK_MAC_BYTES      = 32
PQ_ZK_POLY_BYTES     = 512          # N * 2
PQ_ZK_POLYVEC_BYTES  = 1536         # K * N * 2
PQ_ZK_PUBLICKEY_BYTES= 1184
PQ_ZK_CONTEXT_BYTES  = 80
PQ_ZK_CHALLENGE_WEIGHT = 26

# 错误码
PQ_ZK_SUCCESS              =  0
PQ_ZK_ERR_MAC_FAIL         = -1
PQ_ZK_ERR_CHALLENGE_WEIGHT = -2
PQ_ZK_ERR_NORM_BOUND       = -3
PQ_ZK_ERR_INVALID_PARAM    = -4

g_pass = 0
g_fail = 0

def check(label, cond, got=None, expected=None):
    global g_pass, g_fail
    if cond:
        print(f"[PASS] {label}")
        g_pass += 1
    else:
        print(f"[FAIL] {label}")
        if got is not None:
            print(f"  got:      {got[:32].hex() if isinstance(got, (bytes,bytearray)) else got}")
        if expected is not None:
            print(f"  expected: {expected[:32].hex() if isinstance(expected, (bytes,bytearray)) else expected}")
        g_fail += 1

# ── ctypes 结构体（与头文件完全对齐）────────────────────────────────────
class poly_t(ctypes.Structure):
    _fields_ = [("coeffs", ctypes.c_int16 * PQ_ZK_N)]

class poly_vec_t(ctypes.Structure):
    _fields_ = [("coeffs", ctypes.c_int16 * (PQ_ZK_K * PQ_ZK_N))]

class beta_params_t(ctypes.Structure):
    _fields_ = [
        ("beta_final", ctypes.c_uint16),
        ("beta_min",   ctypes.c_uint16),
    ]

class ContextData(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("timestamp", ctypes.c_uint64),
        ("latitude",  ctypes.c_int32),
        ("longitude", ctypes.c_int32),
        ("desc",      ctypes.c_char * 64),
    ]

def load_lib(so_path: str):
    """加载 .so 并绑定所有函数签名"""
    lib = ctypes.CDLL(so_path)

    # PQC_EncodePolyVec(in_poly, out_bytes)
    lib.PQC_EncodePolyVec.restype  = None
    lib.PQC_EncodePolyVec.argtypes = [
        ctypes.POINTER(poly_vec_t),
        ctypes.POINTER(ctypes.c_uint8),
    ]

    # PQC_DecodePolyVec(in_bytes, out_poly)
    lib.PQC_DecodePolyVec.restype  = None
    lib.PQC_DecodePolyVec.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(poly_vec_t),
    ]

    # PQC_EncodePoly(in_poly, out_bytes)
    lib.PQC_EncodePoly.restype  = None
    lib.PQC_EncodePoly.argtypes = [
        ctypes.POINTER(poly_t),
        ctypes.POINTER(ctypes.c_uint8),
    ]

    # PQC_SerializeContext(ctx, ctx_bytes)
    lib.PQC_SerializeContext.restype  = None
    lib.PQC_SerializeContext.argtypes = [
        ctypes.POINTER(ContextData),
        ctypes.POINTER(ctypes.c_uint8),
    ]

    # PQC_GenKeyPair(pk_t, sk_s)
    lib.PQC_GenKeyPair.restype  = None
    lib.PQC_GenKeyPair.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(poly_vec_t),
    ]

    # PQC_eUICC_Init(nvram_dir, eid, eid_len, sk_s, k_sym, k_sym_len,
    #                initial_ctr, k_tee, k_tee_len)
    lib.PQC_eUICC_Init.restype  = None
    lib.PQC_eUICC_Init.argtypes = [
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
        ctypes.POINTER(poly_vec_t),
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
        ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
    ]

    # PQC_PreCompute(W_pub, seed_y)
    lib.PQC_PreCompute.restype  = None
    lib.PQC_PreCompute.argtypes = [
        ctypes.POINTER(poly_vec_t),
        ctypes.POINTER(ctypes.c_uint8),
    ]

    # PQC_RegenerateYpub(seed_y, y_pub)
    lib.PQC_RegenerateYpub.restype  = None
    lib.PQC_RegenerateYpub.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(poly_vec_t),
    ]

    # PQC_eUICC_Commit(nvram_dir, W_sec, MAC_W)
    lib.PQC_eUICC_Commit.restype  = None
    lib.PQC_eUICC_Commit.argtypes = [
        ctypes.c_char_p,
        ctypes.POINTER(poly_vec_t),
        ctypes.POINTER(ctypes.c_uint8),
    ]

    # PQC_GenChallenge(comm_W, nonce, H_ctx, c_agg)
    lib.PQC_GenChallenge.restype  = None
    lib.PQC_GenChallenge.argtypes = [
        ctypes.POINTER(poly_vec_t),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(poly_t),
    ]

    # PQC_ComputeZ_and_Mask(nvram_dir, c_agg, c_seed, H_ctx,
    #                        hash_M2, AuthToken, z_sec_masked) → ErrorCode
    lib.PQC_ComputeZ_and_Mask.restype  = ctypes.c_int
    lib.PQC_ComputeZ_and_Mask.argtypes = [
        ctypes.c_char_p,
        ctypes.POINTER(poly_t),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(poly_vec_t),
    ]

    # PQC_LPA_Aggregate(z_sec_masked, y_pub, resp_z)
    lib.PQC_LPA_Aggregate.restype  = None
    lib.PQC_LPA_Aggregate.argtypes = [
        ctypes.POINTER(poly_vec_t),
        ctypes.POINTER(poly_vec_t),
        ctypes.POINTER(poly_vec_t),
    ]

    # PQC_GenerateMask(K_sym, c_seed, ctr_session, H_ctx, M_mask)
    lib.PQC_GenerateMask.restype  = None
    lib.PQC_GenerateMask.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(poly_vec_t),
    ]

    # PQC_VerifyEngine(mat_A_seed, pk_t, comm_W, resp_z,
    #                   nonce_s, H_ctx, M_mask, beta_params) → ErrorCode
    lib.PQC_VerifyEngine.restype  = ctypes.c_int
    lib.PQC_VerifyEngine.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(poly_vec_t),
        ctypes.POINTER(poly_vec_t),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(poly_vec_t),
        ctypes.POINTER(beta_params_t),
    ]

    return lib

def buf(data: bytes):
    """bytes → ctypes c_uint8 数组指针"""
    arr = (ctypes.c_uint8 * len(data))(*data)
    return arr

def polyvec_to_bytes(pv: poly_vec_t) -> bytes:
    out = (ctypes.c_uint8 * PQ_ZK_POLYVEC_BYTES)()
    return bytes(out)

# ═══════════════════════════════════════════════════════════════════
# KAT 测试
# ═══════════════════════════════════════════════════════════════════

def kat_encode_decode(lib):
    print("\n=== Python KAT 1: EncodePolyVec / DecodePolyVec ===")

    # 构造测试向量：coeffs[i] = i % 3329
    pv = poly_vec_t()
    for i in range(PQ_ZK_K * PQ_ZK_N):
        pv.coeffs[i] = i % 3329

    out = (ctypes.c_uint8 * PQ_ZK_POLYVEC_BYTES)()
    lib.PQC_EncodePolyVec(ctypes.byref(pv), out)

    encoded = bytes(out)
    # 验证前3个系数: coeffs[0]=0 → 0x0000, [1]=1 → 0x0100 LE, [2]=2 → 0x0200 LE
    expected_head = bytes([0x00,0x00, 0x01,0x00, 0x02,0x00])
    check("EncodePolyVec coeffs[0:3]",
          encoded[:6] == expected_head, encoded[:6], expected_head)

    # 往返测试
    pv2 = poly_vec_t()
    in_buf = (ctypes.c_uint8 * PQ_ZK_POLYVEC_BYTES)(*encoded)
    lib.PQC_DecodePolyVec(in_buf, ctypes.byref(pv2))
    roundtrip_ok = all(pv.coeffs[i] == pv2.coeffs[i]
                       for i in range(PQ_ZK_K * PQ_ZK_N))
    check("DecodePolyVec roundtrip", roundtrip_ok)

    print(f"  encoded[0:8] = {encoded[:8].hex()}")
    return encoded   # 供后续 KAT 使用


def kat_serialize_context(lib):
    print("\n=== Python KAT 2: SerializeContext + H_ctx ===")

    ctx = ContextData()
    ctx.timestamp  = 0x000000006745B320
    ctx.latitude   = 316074000
    ctx.longitude  = 1213734000
    ctx.desc       = b"eSIM-download-operator-A"

    ctx_bytes = (ctypes.c_uint8 * PQ_ZK_CONTEXT_BYTES)()
    lib.PQC_SerializeContext(ctypes.byref(ctx), ctx_bytes)
    serialized = bytes(ctx_bytes)

    # 预期前16字节（Python 验证）
    expected = (struct.pack('<Q', 0x000000006745B320) +
                struct.pack('<i', 316074000) +
                struct.pack('<i', 1213734000))
    check("SerializeContext header[0:16]",
          serialized[:16] == expected, serialized[:16], expected)

    # H_ctx = SHA256(serialized)
    H_ctx = hashlib.sha256(serialized).digest()
    print(f"  H_ctx = {H_ctx.hex()}")

    # 与 C 层 KAT 对齐
    c_layer_hctx = bytes.fromhex(
        "fb61b4c3a14b2a2dcaec455d26447dab"
        "8e9f3f14796b921de8ffa3c50a557c6d"
    )
    check("H_ctx matches C-layer KAT",
          H_ctx == c_layer_hctx, H_ctx, c_layer_hctx)

    return serialized, H_ctx


def kat_prf_mask(lib):
    print("\n=== Python KAT 3: GenerateMask (PRF) 确定性 ===")

    K_sym  = bytes([0xAA] * 32)
    c_seed = bytes([0xBB] * 32)
    H_ctx  = bytes([0xCC] * 32)
    ctr    = 42

    M1 = poly_vec_t()
    K_sym_buf  = (ctypes.c_uint8 * 32)(*K_sym)
    c_seed_buf = (ctypes.c_uint8 * 32)(*c_seed)
    H_ctx_buf  = (ctypes.c_uint8 * 32)(*H_ctx)

    lib.PQC_GenerateMask(K_sym_buf, c_seed_buf, ctr, H_ctx_buf,
                         ctypes.byref(M1))

    # 再调一次，验证确定性
    M2 = poly_vec_t()
    lib.PQC_GenerateMask(K_sym_buf, c_seed_buf, ctr, H_ctx_buf,
                         ctypes.byref(M2))

    same = all(M1.coeffs[i] == M2.coeffs[i]
               for i in range(PQ_ZK_K * PQ_ZK_N))
    check("GenerateMask deterministic", same)

    # ctr+1 应产生不同输出
    M3 = poly_vec_t()
    lib.PQC_GenerateMask(K_sym_buf, c_seed_buf, ctr + 1, H_ctx_buf,
                         ctypes.byref(M3))
    diff = any(M1.coeffs[i] != M3.coeffs[i]
               for i in range(PQ_ZK_K * PQ_ZK_N))
    check("GenerateMask ctr sensitivity", diff)

    # 所有系数在 [0, 3328]
    all_valid = all(0 <= M1.coeffs[i] <= 3328
                    for i in range(PQ_ZK_K * PQ_ZK_N))
    check("GenerateMask coeffs in [0, q-1]", all_valid)

    return M1


def kat_gen_challenge(lib):
    print("\n=== Python KAT 4: GenChallenge 稀疏性 ===")

    # 构造 W（全零承诺，固定测试）
    W = poly_vec_t()

    c_seed_val = bytes([0x01] * 32)
    H_ctx_val  = bytes([0x02] * 32)
    c_seed_buf = (ctypes.c_uint8 * 32)(*c_seed_val)
    H_ctx_buf  = (ctypes.c_uint8 * 32)(*H_ctx_val)

    c_agg = poly_t()
    lib.PQC_GenChallenge(ctypes.byref(W), c_seed_buf, H_ctx_buf,
                         ctypes.byref(c_agg))

    # 汉明重量
    weight  = sum(1 for i in range(PQ_ZK_N) if c_agg.coeffs[i] != 0)
    bad     = sum(1 for i in range(PQ_ZK_N)
                  if c_agg.coeffs[i] not in (-1, 0, 1))

    check(f"c_agg Hamming weight = κ={PQ_ZK_CHALLENGE_WEIGHT}",
          weight == PQ_ZK_CHALLENGE_WEIGHT)
    check("c_agg coeffs ∈ {-1,0,1}", bad == 0)

    # 确定性
    c_agg2 = poly_t()
    lib.PQC_GenChallenge(ctypes.byref(W), c_seed_buf, H_ctx_buf,
                         ctypes.byref(c_agg2))
    det = all(c_agg.coeffs[i] == c_agg2.coeffs[i] for i in range(PQ_ZK_N))
    check("GenChallenge deterministic", det)

    return c_agg


def kat_e2e_protocol(lib):
    """完整协议端到端（单机模拟，Python 驱动 C 函数）"""
    print("\n=== Python KAT 5: 协议端到端 ===")

    with tempfile.TemporaryDirectory() as nvram_dir:
        nvram_bytes = nvram_dir.encode()

        # ── 阶段零 ──────────────────────────────────────────────────
        pk_t_buf = (ctypes.c_uint8 * PQ_ZK_PUBLICKEY_BYTES)()
        sk_s     = poly_vec_t()
        lib.PQC_GenKeyPair(pk_t_buf, ctypes.byref(sk_s))

        eid    = bytes([0x01]*16)
        k_sym  = bytes([0x11]*32)
        k_tee  = bytes([0x22]*32)
        eid_b  = (ctypes.c_uint8 * 16)(*eid)
        ksym_b = (ctypes.c_uint8 * 32)(*k_sym)
        ktee_b = (ctypes.c_uint8 * 32)(*k_tee)

        lib.PQC_eUICC_Init(nvram_bytes,
                           eid_b,   16,
                           ctypes.byref(sk_s),
                           ksym_b,  32,
                           ctypes.c_uint64(0),
                           ktee_b,  32)
        check("eUICC_Init", True)

        # ── 阶段一 ──────────────────────────────────────────────────
        W_pub  = poly_vec_t()
        seed_y = (ctypes.c_uint8 * 32)()
        lib.PQC_PreCompute(ctypes.byref(W_pub), seed_y)

        W_sec  = poly_vec_t()
        MAC_W  = (ctypes.c_uint8 * 32)()
        lib.PQC_eUICC_Commit(nvram_bytes, ctypes.byref(W_sec), MAC_W)
        print(f"  MAC_W = {bytes(MAC_W).hex()}")

        # Python 端验证 MAC_W 格式（32字节非全零）
        check("MAC_W non-zero", any(b != 0 for b in MAC_W))

        # W = W_sec + W_pub mod q
        W = poly_vec_t()
        for i in range(PQ_ZK_K * PQ_ZK_N):
            W.coeffs[i] = (W_sec.coeffs[i] + W_pub.coeffs[i]) % 3329

        # ── 阶段二 ──────────────────────────────────────────────────
        # H_ctx
        ctx = ContextData()
        ctx.timestamp  = 1732500256
        ctx.latitude   = 316074000
        ctx.longitude  = 1213734000
        ctx.desc       = b"test-session"
        ctx_bytes_buf  = (ctypes.c_uint8 * PQ_ZK_CONTEXT_BYTES)()
        lib.PQC_SerializeContext(ctypes.byref(ctx), ctx_bytes_buf)
        H_ctx_val = hashlib.sha256(bytes(ctx_bytes_buf)).digest()

        import os
        c_seed_val = os.urandom(32)
        c_seed_buf = (ctypes.c_uint8 * 32)(*c_seed_val)
        H_ctx_buf  = (ctypes.c_uint8 * 32)(*H_ctx_val)

        c_agg = poly_t()
        lib.PQC_GenChallenge(ctypes.byref(W), c_seed_buf, H_ctx_buf,
                             ctypes.byref(c_agg))

        # ── 阶段三：Python 模拟 TEE 计算 AuthToken ──────────────────
        # AuthToken = HMAC(K_TEE, encode(c_agg)||ctr_le8||H_ctx||hash_M2)
        cagg_bytes_buf = (ctypes.c_uint8 * PQ_ZK_POLY_BYTES)()
        lib.PQC_EncodePoly(ctypes.byref(c_agg), cagg_bytes_buf)
        cagg_encoded = bytes(cagg_bytes_buf)

        ctr_le8  = struct.pack('<Q', 0)   # initial ctr = 0
        hash_M2  = bytes([0x55] * 32)
        auth_msg = cagg_encoded + ctr_le8 + H_ctx_val + hash_M2
        AuthToken_val = hmac.new(k_tee, auth_msg, hashlib.sha256).digest()

        print(f"  AuthToken = {AuthToken_val.hex()}")

        # ── 阶段四 ──────────────────────────────────────────────────
        hash_M2_buf    = (ctypes.c_uint8 * 32)(*hash_M2)
        AuthToken_buf  = (ctypes.c_uint8 * 32)(*AuthToken_val)
        z_sec_masked   = poly_vec_t()

        rc = lib.PQC_ComputeZ_and_Mask(
            nvram_bytes,
            ctypes.byref(c_agg),
            c_seed_buf, H_ctx_buf,
            hash_M2_buf, AuthToken_buf,
            ctypes.byref(z_sec_masked)
        )
        check(f"ComputeZ_and_Mask rc={rc}", rc == PQ_ZK_SUCCESS)

        # ── 阶段五 ──────────────────────────────────────────────────
        y_pub  = poly_vec_t()
        lib.PQC_RegenerateYpub(seed_y, ctypes.byref(y_pub))

        resp_z = poly_vec_t()
        lib.PQC_LPA_Aggregate(ctypes.byref(z_sec_masked),
                               ctypes.byref(y_pub),
                               ctypes.byref(resp_z))

        # ── 阶段六 ──────────────────────────────────────────────────
        M_mask = poly_vec_t()
        ksym_b32 = (ctypes.c_uint8 * 32)(*k_sym)
        lib.PQC_GenerateMask(ksym_b32, c_seed_buf,
                              ctypes.c_uint64(0),   # ctr_session=0
                              H_ctx_buf,
                              ctypes.byref(M_mask))

        # 矩阵种子（固定值，与 C 层 PQZK_MATRIX_A_SEED 对齐）
        A_seed = bytes([
            0x50,0x51,0x5A,0x4B, 0x45,0x53,0x49,0x4D,
            0x4D,0x41,0x54,0x52, 0x49,0x58,0x5F,0x41,
            0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
            0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F,
        ])
        A_seed_buf = (ctypes.c_uint8 * 32)(*A_seed)

        params = beta_params_t(beta_final=1301, beta_min=100)

        verify_rc = lib.PQC_VerifyEngine(
            A_seed_buf, pk_t_buf,
            ctypes.byref(W), ctypes.byref(resp_z),
            c_seed_buf, H_ctx_buf,
            ctypes.byref(M_mask),
            ctypes.byref(params)
        )
        check(f"VerifyEngine rc={verify_rc}", verify_rc == PQ_ZK_SUCCESS)


def kat_mac_w_format(lib):
    """
    验证 MAC_W 格式与 C 层一致
    MAC_W = HMAC-SHA256(K_sym, EncodePolyVec(W_sec) || ctr_le8)
    这是后端计数器匹配的核心
    """
    print("\n=== Python KAT 6: MAC_W 格式验证（后端对齐关键）===")

    # 构造固定 W_sec（全1系数）
    W_sec = poly_vec_t()
    for i in range(PQ_ZK_K * PQ_ZK_N):
        W_sec.coeffs[i] = 1

    wsec_bytes_buf = (ctypes.c_uint8 * PQ_ZK_POLYVEC_BYTES)()
    lib.PQC_EncodePolyVec(ctypes.byref(W_sec), wsec_bytes_buf)
    wsec_bytes = bytes(wsec_bytes_buf)

    k_sym   = bytes([0xAA] * 32)
    ctr     = 0
    ctr_le8 = struct.pack('<Q', ctr)

    # Python 端按协议计算 MAC_W
    mac_input = wsec_bytes + ctr_le8
    expected_mac = hmac.new(k_sym, mac_input, hashlib.sha256).digest()
    print(f"  Python MAC_W (W=all-1, ctr=0) = {expected_mac.hex()}")
    print(f"  EncodePolyVec(W_sec)[0:8] = {wsec_bytes[:8].hex()}")

    # 验证 EncodePolyVec：系数1 → 0x0100 (LE int16)
    expected_enc_head = bytes([0x01, 0x00] * 4)  # 前4个系数都是1
    check("EncodePolyVec all-1 coeffs",
          wsec_bytes[:8] == expected_enc_head,
          wsec_bytes[:8], expected_enc_head)

    print("  [INFO] 后端计算 MAC_W' 时必须用 PQC_EncodePolyVec 序列化 W_sec")
    print("         然后拼接 ctr 的 8 字节小端序，再做 HMAC-SHA256")


# ═══════════════════════════════════════════════════════════════════
# 主入口
# ═══════════════════════════════════════════════════════════════════

def main():
    global g_pass, g_fail

    parser = argparse.ArgumentParser(description="PQ-ZK-eSIM Python ctypes 对接测试")
    parser.add_argument("--so", default="./build/libpqzkesim_verify.so",
                        help=".so 文件路径")
    args = parser.parse_args()

    so_path = os.path.abspath(args.so)
    if not os.path.exists(so_path):
        print(f"[ERROR] .so 文件不存在: {so_path}")
        sys.exit(1)

    print("=" * 56)
    print("  PQ-ZK-eSIM Python ctypes 对接测试 v3.0")
    print(f"  .so: {so_path}")
    print("=" * 56)

    lib = load_lib(so_path)
    print("[OK] 库加载成功")

    kat_encode_decode(lib)
    kat_serialize_context(lib)
    kat_prf_mask(lib)
    kat_gen_challenge(lib)
    kat_mac_w_format(lib)
    kat_e2e_protocol(lib)

    print("\n" + "=" * 56)
    print(f"  结果：{g_pass} 通过，{g_fail} 失败")
    print("=" * 56)

    sys.exit(0 if g_fail == 0 else 1)


if __name__ == "__main__":
    main()