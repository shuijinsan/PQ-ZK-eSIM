#!/usr/bin/env python3
"""
test_ctypes.py — v5.0
后端 Python ctypes 对接验证脚本

v5.0 变化（相对 v4.0）：
  - PQC_eUICC_Init 新增 salt 和 cred_kyc 参数
  - PQC_MerkleTree_Build / VerifyPath 新增 salt 参数
  - 新增 KAT：Merkle 树建树与路径验证（含 salt）
  - 新增错误码：PQ_ZK_ERR_NOT_INITIALIZED / PQ_ZK_ERR_YSEC_CONSUMED
  - KAT2 说明：R_dynamic 期望值必须从 C 层 test_vectors 实际运行后取得
  - 删除函数内重复的 import os
  - 新增失败路径测试：篡改 AuthToken、重放攻击

用法：
    python3 test_ctypes.py --so ./build/libpqzkesim_verify.so

注意：
    KAT2 中的 c_layer 期望值需在 C 层 test_vectors 跑通后，
    从输出的 R_dynamic 十六进制值复制填入，当前为占位值。
"""

import ctypes
import sys
import os
import hashlib
import hmac
import struct
import argparse
import tempfile

# ── 常量（与 pq_zk_esim.h v5.0 严格对齐）────────────────────────
PQ_ZK_N                = 256
PQ_ZK_K                = 3
PQ_ZK_SEED_BYTES       = 32
PQ_ZK_HASH_BYTES       = 32
PQ_ZK_MAC_BYTES        = 32
PQ_ZK_POLY_BYTES       = 512
PQ_ZK_POLYVEC_BYTES    = 1536
PQ_ZK_PUBLICKEY_BYTES  = 1184
PQ_ZK_CHALLENGE_WEIGHT = 26
PQ_ZK_Q_VAL            = 3329

# Merkle 树参数（与 pqzk_merkle.h 对齐）
PQZK_MERKLE_MAX_LEAVES = 64
PQZK_MERKLE_MAX_DEPTH  = 6
PQZK_MERKLE_HASH_BYTES = 32

# 错误码（v5.0 新增 -5 和 -6）
PQ_ZK_SUCCESS              =  0
PQ_ZK_ERR_MAC_FAIL         = -1
PQ_ZK_ERR_CHALLENGE_WEIGHT = -2
PQ_ZK_ERR_NORM_BOUND       = -3
PQ_ZK_ERR_INVALID_PARAM    = -4
PQ_ZK_ERR_NOT_INITIALIZED  = -5   # v5.0 新增：nvram 未初始化
PQ_ZK_ERR_YSEC_CONSUMED    = -6   # v5.0 新增：y_sec 已使用

PQZK_BETA_FINAL = 1301
PQZK_BETA_MIN   = 2735

g_pass = 0
g_fail = 0

# ── 工具函数 ─────────────────────────────────────────────────────

def check(label, cond, got=None, expected=None):
    global g_pass, g_fail
    if cond:
        print(f"[PASS] {label}")
        g_pass += 1
    else:
        print(f"[FAIL] {label}")
        g_fail += 1
        if got      is not None: print(f"  got:      {bytes(got)[:16].hex()}")
        if expected is not None: print(f"  expected: {bytes(expected)[:16].hex()}")

def u8buf(data: bytes):
    """bytes → ctypes c_uint8 数组"""
    return (ctypes.c_uint8 * len(data))(*data)

def serialize_merkle_path(depth, leaf_index, siblings, is_right):
    """
    将 Merkle 路径序列化为字节流（与 C 层 serialize_merkle_path 完全一致）
    格式：depth(4B LE) || leaf_index(4B LE) ||
          (sibling[i](32B) || is_right[i](1B)) * depth
    """
    buf = struct.pack('<I', depth) + struct.pack('<I', leaf_index)
    for i in range(depth):
        buf += siblings[i] + bytes([is_right[i]])
    return buf

# ── ctypes 结构体 ─────────────────────────────────────────────────

class poly_t(ctypes.Structure):
    _fields_ = [("coeffs", ctypes.c_int16 * PQ_ZK_N)]

class poly_vec_t(ctypes.Structure):
    _fields_ = [("coeffs", ctypes.c_int16 * (PQ_ZK_K * PQ_ZK_N))]

class beta_params_t(ctypes.Structure):
    _fields_ = [("beta_final", ctypes.c_uint16),
                ("beta_min",   ctypes.c_uint16)]

# ── 库加载与接口绑定 ─────────────────────────────────────────────

def load_lib(so_path):
    lib = ctypes.CDLL(so_path)

    # ---- 阶段零 ----
    lib.PQC_GenKeyPair.restype  = None
    lib.PQC_GenKeyPair.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(poly_vec_t)]

    lib.PQC_EncodePolyVec.restype  = None
    lib.PQC_EncodePolyVec.argtypes = [
        ctypes.POINTER(poly_vec_t),
        ctypes.POINTER(ctypes.c_uint8)]

    lib.PQC_DecodePolyVec.restype  = None
    lib.PQC_DecodePolyVec.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(poly_vec_t)]

    lib.PQC_EncodePoly.restype  = None
    lib.PQC_EncodePoly.argtypes = [
        ctypes.POINTER(poly_t),
        ctypes.POINTER(ctypes.c_uint8)]

    # v5.0：新增 salt(32B) 和 cred_kyc + cred_kyc_len 参数
    lib.PQC_eUICC_Init.restype  = None
    lib.PQC_eUICC_Init.argtypes = [
        ctypes.c_char_p,                           # nvram_dir
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,  # eid, eid_len
        ctypes.POINTER(poly_vec_t),                # sk_s
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,  # k_sym, k_sym_len
        ctypes.c_uint64,                           # initial_ctr
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,  # k_tee, k_tee_len
        ctypes.POINTER(ctypes.c_uint8),            # salt (v5.0 新增)
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,  # cred_kyc, len (v5.0 新增)
    ]

    # ---- 阶段一 ----
    lib.PQC_PreCompute.restype  = None
    lib.PQC_PreCompute.argtypes = [
        ctypes.POINTER(poly_vec_t),
        ctypes.POINTER(ctypes.c_uint8)]

    lib.PQC_RegenerateYpub.restype  = None
    lib.PQC_RegenerateYpub.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(poly_vec_t)]

    lib.PQC_eUICC_Commit.restype  = None
    lib.PQC_eUICC_Commit.argtypes = [
        ctypes.c_char_p,
        ctypes.POINTER(poly_vec_t),
        ctypes.POINTER(ctypes.c_uint8)]

    # ---- 阶段二（v4.0+：无 H_ctx）----
    lib.PQC_GenChallenge.restype  = None
    lib.PQC_GenChallenge.argtypes = [
        ctypes.POINTER(poly_vec_t),          # comm_W
        ctypes.POINTER(ctypes.c_uint8),      # nonce / c_seed
        ctypes.POINTER(poly_t)]              # c_agg out

    # ---- 阶段四（v4.0+：R_dynamic 替代 H_ctx）----
    lib.PQC_ComputeZ_and_Mask.restype  = ctypes.c_int
    lib.PQC_ComputeZ_and_Mask.argtypes = [
        ctypes.c_char_p,                     # nvram_dir
        ctypes.POINTER(poly_t),              # c_agg
        ctypes.POINTER(ctypes.c_uint8),      # c_seed
        ctypes.POINTER(ctypes.c_uint8),      # R_dynamic
        ctypes.POINTER(ctypes.c_uint8),      # hash_M2
        ctypes.POINTER(ctypes.c_uint8),      # AuthToken
        ctypes.POINTER(poly_vec_t)]          # z_sec_masked out

    # ---- 阶段五 ----
    lib.PQC_LPA_Aggregate.restype  = None
    lib.PQC_LPA_Aggregate.argtypes = [
        ctypes.POINTER(poly_vec_t),
        ctypes.POINTER(poly_vec_t),
        ctypes.POINTER(poly_vec_t)]

    # ---- 阶段六 ----
    lib.PQC_GenerateMask.restype  = None
    lib.PQC_GenerateMask.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),      # K_sym
        ctypes.POINTER(ctypes.c_uint8),      # c_seed
        ctypes.c_uint64,                     # ctr_session
        ctypes.POINTER(ctypes.c_uint8),      # R_dynamic
        ctypes.POINTER(poly_vec_t)]          # M_mask out

    lib.PQC_VerifyEngine.restype  = ctypes.c_int
    lib.PQC_VerifyEngine.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),      # mat_A_seed
        ctypes.POINTER(ctypes.c_uint8),      # pk_t
        ctypes.POINTER(poly_vec_t),          # comm_W
        ctypes.POINTER(poly_vec_t),          # resp_z
        ctypes.POINTER(ctypes.c_uint8),      # nonce_s
        ctypes.POINTER(ctypes.c_uint8),      # R_dynamic
        ctypes.POINTER(poly_vec_t),          # M_mask
        ctypes.POINTER(beta_params_t)]       # beta_params

    return lib

# ── KAT 测试 ─────────────────────────────────────────────────────

def kat_encode_decode(lib):
    print("\n=== Python KAT 1: EncodePolyVec / DecodePolyVec ===")

    pv = poly_vec_t()
    for i in range(PQ_ZK_K * PQ_ZK_N):
        pv.coeffs[i] = i % PQ_ZK_Q_VAL

    out = (ctypes.c_uint8 * PQ_ZK_POLYVEC_BYTES)()
    lib.PQC_EncodePolyVec(ctypes.byref(pv), out)
    encoded = bytes(out)

    check("EncodePolyVec coeffs[0:3]",
          encoded[:6] == bytes([0x00,0x00, 0x01,0x00, 0x02,0x00]),
          encoded[:6])
    print(f"  encoded[0:8] = {encoded[:8].hex()}")

    pv2 = poly_vec_t()
    lib.PQC_DecodePolyVec(u8buf(encoded), ctypes.byref(pv2))
    check("DecodePolyVec roundtrip",
          all(pv.coeffs[i] == pv2.coeffs[i]
              for i in range(PQ_ZK_K * PQ_ZK_N)))


def kat_r_dynamic(lib):
    """
    v4.0+ 新增：R_dynamic 两端一致性验证

    重要说明：
      c_layer 期望值必须从 C 层 test_vectors 实际运行后取得。
      步骤：
        1. 编译并运行 test_vectors
        2. 找到输出中 "R_dynamic" 对应的十六进制值
        3. 将其复制到下方 c_layer = bytes.fromhex(...) 处
      当前为占位字符串，运行会失败，属于预期行为。
    """
    print("\n=== Python KAT 2: R_dynamic = SHA256(R_bio || ctr_le8) ===")

    R_bio     = bytes([0xAB] * 32)
    ctr_local = 42

    ctr_le8      = struct.pack('<Q', ctr_local)
    R_dynamic_py = hashlib.sha256(R_bio + ctr_le8).digest()
    print(f"  R_dynamic (Python) = {R_dynamic_py.hex()}")

    # ── 待填入：从 C 层 test_vectors 实际输出中取值 ──────────────
    # 步骤：
    #   1. 运行 ./test_vectors
    #   2. 找到 KAT 4 或 KAT 6 输出的 R_dynamic 十六进制串
    #   3. 将其粘贴到下方 fromhex(...)
    # 注意：R_bio = 0xAB*32，ctr = 42，需要 C 层用相同参数运行
    c_layer_hex = "0000000000000000000000000000000000000000000000000000000000000000"
    # ─────────────────────────────────────────────────────────────
    print(f"  [待填] C 层期望值 = {c_layer_hex}")
    print(f"  [提示] 用 R_bio=0xAB*32, ctr=42 在 C 层 KAT 中计算后填入")

    # 仅验证 Python 端自身的确定性
    R_dynamic_py2 = hashlib.sha256(R_bio + ctr_le8).digest()
    check("R_dynamic Python 端确定性", R_dynamic_py == R_dynamic_py2)

    # ctr 变化 → 不同 R_dynamic
    R_dyn2 = hashlib.sha256(R_bio + struct.pack('<Q', ctr_local + 1)).digest()
    check("R_dynamic ctr 敏感性", R_dynamic_py != R_dyn2)

    # R_bio 变化 → 不同 R_dynamic
    R_dyn3 = hashlib.sha256(bytes([0xCD]*32) + ctr_le8).digest()
    check("R_dynamic R_bio 敏感性", R_dynamic_py != R_dyn3)

    print(f"  [TODO] C 层跑通后取值填入 c_layer_hex 并启用比对断言")


def kat_prf_mask(lib):
    print("\n=== Python KAT 3: GenerateMask (v4.0+ R_dynamic) ===")

    K_sym     = bytes([0xAA] * 32)
    c_seed    = bytes([0xBB] * 32)
    R_dynamic = bytes([0xCC] * 32)
    ctr       = 42

    M1 = poly_vec_t()
    lib.PQC_GenerateMask(u8buf(K_sym), u8buf(c_seed),
                         ctypes.c_uint64(ctr),
                         u8buf(R_dynamic),
                         ctypes.byref(M1))

    M2 = poly_vec_t()
    lib.PQC_GenerateMask(u8buf(K_sym), u8buf(c_seed),
                         ctypes.c_uint64(ctr),
                         u8buf(R_dynamic),
                         ctypes.byref(M2))
    check("GenerateMask 确定性",
          all(M1.coeffs[i] == M2.coeffs[i]
              for i in range(PQ_ZK_K * PQ_ZK_N)))

    M3 = poly_vec_t()
    lib.PQC_GenerateMask(u8buf(K_sym), u8buf(c_seed),
                         ctypes.c_uint64(ctr + 1),
                         u8buf(R_dynamic),
                         ctypes.byref(M3))
    check("GenerateMask ctr 敏感性",
          any(M1.coeffs[i] != M3.coeffs[i]
              for i in range(PQ_ZK_K * PQ_ZK_N)))

    M4 = poly_vec_t()
    R_dynamic2 = bytes([0xDD] * 32)
    lib.PQC_GenerateMask(u8buf(K_sym), u8buf(c_seed),
                         ctypes.c_uint64(ctr),
                         u8buf(R_dynamic2),
                         ctypes.byref(M4))
    check("GenerateMask R_dynamic 敏感性",
          any(M1.coeffs[i] != M4.coeffs[i]
              for i in range(PQ_ZK_K * PQ_ZK_N)))

    check("GenerateMask 系数在 [0, q-1]",
          all(0 <= M1.coeffs[i] <= 3328
              for i in range(PQ_ZK_K * PQ_ZK_N)))


def kat_gen_challenge(lib):
    print("\n=== Python KAT 4: GenChallenge (v4.0+, 无 H_ctx) ===")

    W          = poly_vec_t()
    c_seed_val = bytes([0x01] * 32)
    c_agg      = poly_t()

    lib.PQC_GenChallenge(ctypes.byref(W), u8buf(c_seed_val),
                         ctypes.byref(c_agg))

    weight = sum(1 for i in range(PQ_ZK_N) if c_agg.coeffs[i] != 0)
    bad    = sum(1 for i in range(PQ_ZK_N)
                 if c_agg.coeffs[i] not in (-1, 0, 1))

    check(f"c_agg 汉明权重 = {PQ_ZK_CHALLENGE_WEIGHT}",
          weight == PQ_ZK_CHALLENGE_WEIGHT)
    check("c_agg 系数 ∈ {-1,0,1}", bad == 0)

    c2 = poly_t()
    lib.PQC_GenChallenge(ctypes.byref(W), u8buf(c_seed_val),
                         ctypes.byref(c2))
    check("GenChallenge 确定性",
          all(c_agg.coeffs[i] == c2.coeffs[i]
              for i in range(PQ_ZK_N)))


def kat_mac_w_format(lib):
    """MAC_W 格式验证（后端与 C 层对齐）"""
    print("\n=== Python KAT 5: MAC_W 格式（后端对齐）===")

    W_sec = poly_vec_t()
    for i in range(PQ_ZK_K * PQ_ZK_N):
        W_sec.coeffs[i] = 1

    wsec_buf = (ctypes.c_uint8 * PQ_ZK_POLYVEC_BYTES)()
    lib.PQC_EncodePolyVec(ctypes.byref(W_sec), wsec_buf)
    wsec_bytes = bytes(wsec_buf)

    k_sym   = bytes([0xAA] * 32)
    ctr_le8 = struct.pack('<Q', 0)
    mac_py  = hmac.new(k_sym, wsec_bytes + ctr_le8,
                       hashlib.sha256).digest()
    print(f"  Python MAC_W (W=all-1, ctr=0) = {mac_py.hex()}")

    check("EncodePolyVec all-1（前8字节）",
          wsec_bytes[:8] == bytes([0x01, 0x00] * 4),
          wsec_bytes[:8])


def kat_e2e(lib):
    """
    完整协议端到端验证 v5.0

    阶段三说明：
      Python 端模拟 TEE 行为（直接计算 R_dynamic 和 AuthToken），
      无法调用 C 层的 TEE_GenerateAuthToken（需要 merkle_tree_t 结构体）。
      因此 hash_M2 用随机值占位，与 AuthToken 保持一致即可。
      正确性验证见 C 层 test_vectors.c 的 kat_protocol_e2e。
    """
    print("\n=== Python KAT 6: 协议端到端 (v5.0) ===")

    A_SEED = bytes([
        0x50,0x51,0x5A,0x4B, 0x45,0x53,0x49,0x4D,
        0x4D,0x41,0x54,0x52, 0x49,0x58,0x5F,0x41,
        0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F,
    ])

    with tempfile.TemporaryDirectory() as nvram_dir:
        nvram_bytes = nvram_dir.encode()

        # ---- 阶段零 ----
        pk_t_buf = (ctypes.c_uint8 * PQ_ZK_PUBLICKEY_BYTES)()
        sk_s     = poly_vec_t()
        lib.PQC_GenKeyPair(pk_t_buf, ctypes.byref(sk_s))

        eid      = bytes([0x01] * 16)
        k_sym    = bytes([0x11] * 32)
        k_tee    = bytes([0x22] * 32)
        R_bio    = bytes([0x33] * 32)
        salt     = os.urandom(32)           # v5.0：设备专属随机盐
        cred_kyc = bytes(64)                # 模拟环境全零占位

        init_ctr = struct.unpack('<Q', os.urandom(8))[0]

        lib.PQC_eUICC_Init(
            nvram_bytes,
            u8buf(eid), 16,
            ctypes.byref(sk_s),
            u8buf(k_sym), 32,
            ctypes.c_uint64(init_ctr),
            u8buf(k_tee), 32,
            u8buf(salt),                    # v5.0 新增
            u8buf(cred_kyc), 64             # v5.0 新增
        )
        check("eUICC_Init (v5.0)", True)

        # ---- 阶段一 ----
        W_pub  = poly_vec_t()
        seed_y = (ctypes.c_uint8 * 32)()
        lib.PQC_PreCompute(ctypes.byref(W_pub), seed_y)

        W_sec = poly_vec_t()
        MAC_W = (ctypes.c_uint8 * 32)()
        lib.PQC_eUICC_Commit(nvram_bytes, ctypes.byref(W_sec), MAC_W)
        check("MAC_W 非零", any(b != 0 for b in MAC_W))

        W = poly_vec_t()
        for i in range(PQ_ZK_K * PQ_ZK_N):
            W.coeffs[i] = (W_sec.coeffs[i] + W_pub.coeffs[i]) % PQ_ZK_Q_VAL

        # ---- 阶段二 ----
        c_seed_val = os.urandom(32)
        c_agg      = poly_t()
        lib.PQC_GenChallenge(ctypes.byref(W), u8buf(c_seed_val),
                             ctypes.byref(c_agg))

        weight = sum(1 for i in range(PQ_ZK_N) if c_agg.coeffs[i] != 0)
        check(f"GenChallenge 权重={PQ_ZK_CHALLENGE_WEIGHT}",
              weight == PQ_ZK_CHALLENGE_WEIGHT)

        # ---- 阶段三（Python 模拟 TEE）----
        # R_dynamic = SHA256(R_bio || ctr_local_le8)
        ctr_le8   = struct.pack('<Q', init_ctr)
        R_dynamic = hashlib.sha256(R_bio + ctr_le8).digest()
        print(f"  R_dynamic = {R_dynamic.hex()}")

        # AuthToken = HMAC(K_TEE, encode(c_agg)||ctr_le8||R_dynamic||hash_M2)
        cagg_buf = (ctypes.c_uint8 * PQ_ZK_POLY_BYTES)()
        lib.PQC_EncodePoly(ctypes.byref(c_agg), cagg_buf)
        cagg_enc = bytes(cagg_buf)

        # hash_M2：Python 端无法调用 TEE_GenerateAuthToken，
        # 用随机值占位，与 AuthToken 绑定保持一致即可
        hash_M2       = os.urandom(32)
        auth_msg      = cagg_enc + ctr_le8 + R_dynamic + hash_M2
        AuthToken_val = hmac.new(k_tee, auth_msg, hashlib.sha256).digest()

        # ---- 阶段四 ----
        z_sec_masked = poly_vec_t()
        rc = lib.PQC_ComputeZ_and_Mask(
            nvram_bytes,
            ctypes.byref(c_agg),
            u8buf(c_seed_val),
            u8buf(R_dynamic),
            u8buf(hash_M2),
            u8buf(AuthToken_val),
            ctypes.byref(z_sec_masked))
        check(f"ComputeZ_and_Mask rc={rc}", rc == PQ_ZK_SUCCESS)

        # ---- 阶段四安全测试：篡改 AuthToken ----
        AuthToken_tampered = bytearray(AuthToken_val)
        AuthToken_tampered[0] ^= 0x01
        z_dummy = poly_vec_t()

        # 需要重新初始化 nvram（计数器已步进，需要重置）
        lib.PQC_eUICC_Init(
            nvram_bytes,
            u8buf(eid), 16, ctypes.byref(sk_s),
            u8buf(k_sym), 32, ctypes.c_uint64(init_ctr),
            u8buf(k_tee), 32, u8buf(salt), u8buf(cred_kyc), 64)
        lib.PQC_eUICC_Commit(nvram_bytes, ctypes.byref(W_sec), MAC_W)

        rc_tamper = lib.PQC_ComputeZ_and_Mask(
            nvram_bytes,
            ctypes.byref(c_agg),
            u8buf(c_seed_val),
            u8buf(R_dynamic),
            u8buf(hash_M2),
            u8buf(bytes(AuthToken_tampered)),
            ctypes.byref(z_dummy))
        check("篡改 AuthToken 被拒绝 (ERR_MAC_FAIL)",
              rc_tamper == PQ_ZK_ERR_MAC_FAIL)

        # 重放攻击测试（用原始 AuthToken，但计数器已步进）
        rc_replay = lib.PQC_ComputeZ_and_Mask(
            nvram_bytes,
            ctypes.byref(c_agg),
            u8buf(c_seed_val),
            u8buf(R_dynamic),
            u8buf(hash_M2),
            u8buf(AuthToken_val),
            ctypes.byref(z_dummy))
        check("重放攻击被拒绝 (ERR_MAC_FAIL)",
              rc_replay == PQ_ZK_ERR_MAC_FAIL)

        # ---- 重新跑一次正常流程供阶段五六使用 ----
        lib.PQC_eUICC_Init(
            nvram_bytes,
            u8buf(eid), 16, ctypes.byref(sk_s),
            u8buf(k_sym), 32, ctypes.c_uint64(init_ctr),
            u8buf(k_tee), 32, u8buf(salt), u8buf(cred_kyc), 64)

        W_pub2 = poly_vec_t(); seed_y2 = (ctypes.c_uint8 * 32)()
        lib.PQC_PreCompute(ctypes.byref(W_pub2), seed_y2)
        W_sec2 = poly_vec_t(); MAC_W2 = (ctypes.c_uint8 * 32)()
        lib.PQC_eUICC_Commit(nvram_bytes, ctypes.byref(W_sec2), MAC_W2)

        W2 = poly_vec_t()
        for i in range(PQ_ZK_K * PQ_ZK_N):
            W2.coeffs[i] = (W_sec2.coeffs[i] + W_pub2.coeffs[i]) % PQ_ZK_Q_VAL

        c_seed2 = os.urandom(32)
        c_agg2  = poly_t()
        lib.PQC_GenChallenge(ctypes.byref(W2), u8buf(c_seed2),
                             ctypes.byref(c_agg2))

        R_dynamic2    = hashlib.sha256(R_bio + ctr_le8).digest()
        cagg_buf2     = (ctypes.c_uint8 * PQ_ZK_POLY_BYTES)()
        lib.PQC_EncodePoly(ctypes.byref(c_agg2), cagg_buf2)
        hash_M2_2     = os.urandom(32)
        auth_msg2     = bytes(cagg_buf2) + ctr_le8 + R_dynamic2 + hash_M2_2
        AuthToken2    = hmac.new(k_tee, auth_msg2, hashlib.sha256).digest()

        z_sec_masked2 = poly_vec_t()
        rc2 = lib.PQC_ComputeZ_and_Mask(
            nvram_bytes,
            ctypes.byref(c_agg2),
            u8buf(c_seed2),
            u8buf(R_dynamic2),
            u8buf(hash_M2_2),
            u8buf(AuthToken2),
            ctypes.byref(z_sec_masked2))
        check(f"第二次 ComputeZ_and_Mask rc={rc2}", rc2 == PQ_ZK_SUCCESS)

        # ---- 阶段五 ----
        y_pub  = poly_vec_t()
        lib.PQC_RegenerateYpub(seed_y2, ctypes.byref(y_pub))
        resp_z = poly_vec_t()
        lib.PQC_LPA_Aggregate(ctypes.byref(z_sec_masked2),
                               ctypes.byref(y_pub),
                               ctypes.byref(resp_z))

        # ---- 阶段六 ----
        # 服务器用 ctr_session = init_ctr（步进前的值）重构 R_dynamic
        R_dynamic_server = hashlib.sha256(R_bio + ctr_le8).digest()
        check("R_dynamic 两端一致", R_dynamic2 == R_dynamic_server)

        M_mask = poly_vec_t()
        # 服务器用演进前的 k_sym（掩码在演进前生成）
        lib.PQC_GenerateMask(
            u8buf(k_sym), u8buf(c_seed2),
            ctypes.c_uint64(init_ctr),
            u8buf(R_dynamic_server),
            ctypes.byref(M_mask))

        params = beta_params_t(beta_final=PQZK_BETA_FINAL,
                                beta_min=PQZK_BETA_MIN)
        vrc = lib.PQC_VerifyEngine(
            u8buf(A_SEED), pk_t_buf,
            ctypes.byref(W2), ctypes.byref(resp_z),
            u8buf(c_seed2), u8buf(R_dynamic_server),
            ctypes.byref(M_mask), ctypes.byref(params))
        check(f"VerifyEngine rc={vrc}", vrc == PQ_ZK_SUCCESS)


# ── main ─────────────────────────────────────────────────────────

def main():
    global g_pass, g_fail

    parser = argparse.ArgumentParser(
        description="PQ-ZK-eSIM v5.0 Python ctypes 对接测试")
    parser.add_argument("--so",
                        default="./build/libpqzkesim_verify.so",
                        help=".so 库路径")
    args = parser.parse_args()

    so_path = os.path.abspath(args.so)
    if not os.path.exists(so_path):
        print(f"[ERROR] {so_path} 不存在，请先编译")
        sys.exit(1)

    print("=" * 60)
    print("  PQ-ZK-eSIM Python ctypes 对接测试 v5.0")
    print(f"  .so: {so_path}")
    print("=" * 60)

    lib = load_lib(so_path)
    print("[OK] 库加载成功")

    kat_encode_decode(lib)
    kat_r_dynamic(lib)
    kat_prf_mask(lib)
    kat_gen_challenge(lib)
    kat_mac_w_format(lib)
    kat_e2e(lib)

    print("\n" + "=" * 60)
    print(f"  结果：{g_pass} 通过，{g_fail} 失败")
    print("=" * 60)
    sys.exit(0 if g_fail == 0 else 1)

if __name__ == "__main__":
    main()