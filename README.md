# PQ-ZK-eSIM

## 项目概述

PQ-ZK-eSIM 是一个基于后量子密码学和零知识证明的 eSIM 认证协议实现，专为资源受限的嵌入式环境设计。该项目提供了抗量子攻击的安全认证机制，同时保持高效的执行性能。

<br />

核心特性

### 安全特性

- **后量子安全性**：基于 Kyber-768 算法，抵抗量子计算攻击
- **零知识证明**：通过稀疏挑战和盲化因子实现知识证明而不泄露秘密
- **抗 DoS 攻击**：预检验 MAC 过滤，防止资源耗尽攻击
- **恒定时间执行**：抵抗时序侧信道攻击
- **生物特征集成**：通过 TEE 实现生物特征验证，抵抗 AI 深度伪造攻击
- **前向安全**：密钥演进机制，确保长期安全性

### 性能特性

- **环境分离**：将计算负载分离到 eUICC（资源受限）和 LPA（高性能）环境
- **高效实现**：优化的格密码学操作，减少计算开销
- **跨端兼容性**：支持 Linux 和 Android 平台
- **内存安全**：严格的内存边界检查和安全清零

## 技术规格

### 密码学参数

#### 128位安全强度（默认）

- **多项式环阶数**：256 (N)
- **模块维度**：3 (K) - 对应 Kyber-768
- **模数**：3329 (q)
- **稀疏挑战权重**：26 (κ)
- **外部盲化因子标准差**：104.0 (σ\_pub)
- **无穷范数上界**：1301 (β\_final)
- **欧几里得范数下界**：2735 (β\_min)

#### 256位安全强度（可选）

- **多项式环阶数**：256 (N)
- **模块维度**：3 (K) - 对应 Kyber-768
- **模数**：8191 (q)
- **稀疏挑战权重**：45 (κ)
- **外部盲化因子标准差**：180.0 (σ\_pub)
- **无穷范数上界**：2251 (β\_final)
- **欧几里得范数下界**：3950 (β\_min)

### 性能指标

- **eUICC 执行时间**：约 4.5 ms（符合 5 ms 目标）
- **抗 DoS 性能**：MAC 验证比完整格验证快 900+ 倍
- **验证成功率**：约 98-99%

## 目录结构

```
pq_zk_project/
├── app/            # 应用程序代码
├── build/          # 构建目录
├── CMakeLists.txt  # CMake 构建配置
├── docs/           # 文档目录
├── experiments/    # 实验代码（包含基准测试）
│   └── benchmarks/ # 性能基准测试
├── include/        # 头文件目录
├── src/            # 源代码目录
│   ├── crypto/     # 密码学实现
│   ├── algebra/    # 代数操作
│   ├── platform/   # 平台相关代码
│   └── tee/        # TEE 相关代码
├── scripts/        # 辅助脚本
├── test/           # 测试代码
├── tools/          # 工具脚本（人脸特征提取、注册数据上传等）
└── venv/           # Python 虚拟环境
```

## 安装与构建

### 依赖项

- **CMake** (>= 3.22)
- **C 编译器** (支持 C11 标准)
- **liboqs** (后量子密码学库)
- **OpenSSL** (>= 3.0) 或 BoringSSL (Android)
- **Python 3** (用于可视化和分析)

### 构建步骤

1. **克隆项目**
   ```bash
   git clone <repository-url>
   cd pq_zk_project
   ```
2. **配置构建**
   ```bash
   mkdir -p build
   cd build
   cmake ..
   ```
3. **编译项目**
   ```bash
   make -j4  # 使用 4 个并行线程
   ```
4. **运行测试**
   ```bash
   ./test_vectors  # 运行测试向量
   ./bench_pqzkesim --perf  # 运行128位安全强度性能测试
   ```

### 构建256位安全强度版本

1. **创建单独的构建目录**
   ```bash
   mkdir -p build_256bit
   cd build_256bit
   cmake ..
   ```
2. **编译256位安全强度版本**
   ```bash
   make -j4
   ```
3. **运行256位安全强度测试**
   ```bash
   ./bench_pqzkesim_256bit --perf  # 运行256位安全强度性能测试
   ./bench_pqzkesim_256bit --grid  # 运行256位安全强度参数网格搜索
   ```

## 使用方法

### 软件使用流程

#### 线下阶段（只做一次，模拟营业厅）

1. **提取人脸特征**
   ```bash
   python3 tools/gen_face_feature.py --img face.jpg --out features.bin
   ```
2. **初始化 eUICC（模拟 NFC/USB OOB 激活）**
   ```bash
   ./pqzkesim_setup --nvram /tmp/euicc \
                    --face features.bin \
                    --mno-id MNO_A_SIM_001
   ```
3. **把 registration\_data.bin 提交给后端（模拟上传）**
   ```bash
   python3 tools/upload_registration.py --file registration_data.bin
   ```

#### 线上阶段（每次使用）

1. **认证**
   ```bash
   ./pqzkesim --auth --nvram /tmp/euicc
   ```
2. **切换运营商（也需要短距安全信道，这里模拟）**
   ```bash
   ./pqzkesim --switch --nvram /tmp/euicc --mno-b-id MNO_B_SIM_001
   ```

### 核心 API

#### 1. 密钥生成

```c
uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES];
poly_vec_t sk_s;
PQC_GenKeyPair(pk_t, &sk_s);
```

#### 2. eUICC 初始化

```c
PQC_eUICC_Init(nvram_dir, eid, eid_len, &sk_s, k_sym, k_sym_len, initial_ctr, k_tee, k_tee_len, salt, cred_kyc, cred_kyc_len);
```

#### 3. 认证流程

```c
// 阶段一：承诺生成
PQC_PreCompute(&W_pub, seed_y);
PQC_eUICC_Commit(nvram_dir, &W_sec, MAC_W);

// 阶段二：挑战生成
PQC_GenChallenge(&W, c_seed, &c_agg);

// 阶段三：TEE 生物鉴权
TEE_GenerateAuthToken(nvram_dir, &c_agg, R_bio, tree, M1, k_tee, R_dynamic_out, M2_out, AuthToken_out);

// 阶段四：掩码协同计算
PQC_ComputeZ_and_Mask(nvram_dir, &c_agg, c_seed, R_dynamic, hash_M2, AuthToken, &z_sec_masked);

// 阶段五：LPA 聚合
PQC_RegenerateYpub(seed_y, &y_pub);
PQC_LPA_Aggregate(&z_sec_masked, &y_pub, &resp_z);

// 阶段六：服务器验证
PQC_GenerateMask(k_sym, c_seed, ctr_session, R_dynamic, &M_mask);
beta_params_t params = PQZK_DEFAULT_BETA_PARAMS;
PQC_VerifyEngine(PQZK_MATRIX_A_SEED, pk_t, &W, &resp_z, c_seed, R_dynamic, &M_mask, &params);
```

## 测试与分析

### 性能测试

#### 128位安全强度测试

```bash
# 运行性能基准测试
./bench_pqzkesim --perf

# 运行抗 DoS 攻击测试
./bench_pqzkesim --dos

# 运行恒定时间执行测试
./bench_pqzkesim --constant

# 运行参数网格搜索
./bench_pqzkesim --grid
```

#### 256位安全强度测试

```bash
# 运行性能基准测试
./bench_pqzkesim_256bit --perf

# 运行参数网格搜索
./bench_pqzkesim_256bit --grid
```

### 可视化分析

```bash
# 生成安全特性比较
python3 scripts/security_comparison.py

# 生成高级可视化图表
python3 scripts/advanced_visualization.py

# 生成128位安全强度参数网格搜索分析
python3 scripts/Grid_search.py

# 生成256位安全强度参数网格搜索分析
python3 scripts/Grid_search_256bit.py
```

## 安全特性比较

| 特性 / 攻击向量      | GSMA RSP | PQ-eSIM | Hint-MLWE | PQ-ZK-eSIM |
| -------------- | -------- | ------- | --------- | ---------- |
| 后量子安全性         | ×        | ✓       | ✓         | ✓          |
| 零知识隐私          | ×        | ×       | ✓         | ✓          |
| 抗 DoS / 同步机制   | ×        | ×       | ×         | ✓          |
| 恒定时间执行         | ✓        | ×       | ×         | ✓          |
| 生物特征 AI 深度伪造抵抗 | ×        | ×       | ×         | ✓          |

## 平台支持

- **Linux x86\_64**：完整功能支持
- **Android**：通过 NDK 交叉编译支持
- **资源受限设备**：优化的 eUICC 执行路径

## 安全注意事项

1. **密钥管理**：私钥必须安全存储在 eUICC 的安全区域
2. **参数选择**：使用默认参数，不要随意修改安全参数
3. **内存安全**：确保所有敏感数据在使用后被安全清零
4. **防重放**：实现适当的计数器管理和同步机制
5. **定期更新**：及时应用安全补丁和更新

## 许可证

本项目采用 MIT 许可证。详见 LICENSE 文件。

## 引用

如果您在研究或产品中使用本项目，请引用以下信息：

```
PQ-ZK-eSIM: Post-Quantum Zero-Knowledge Authentication for eSIM
```

## 联系方式

如有问题或建议，请通过以下方式联系：

- 项目维护者：\[Your Name]
- 电子邮件：\[<your.email@example.com>]
- 项目地址：\[repository-url]

***

**版本**：v5.0
**最后更新**：2026-04-15
