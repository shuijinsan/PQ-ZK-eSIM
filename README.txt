# PQ-ZK-eSIM — Artifact Evaluation

后量子零知识 eSIM 身份认证协议。本仓库是 ACSAC 2026 Artifact Evaluation 的提交物，可在陌生环境独立安装、运行，并复现论文《PQ-ZK-eSIM: Post-Quantum Zero-Knowledge Identity Authentication for eSIM》的主要实验结果。

核心思想：把抗量子认证的计算负担从 eUICC 卸载到 LPA/Server —— eUICC 只做稀疏三元加法（无 NTT、无高斯采样），重格运算由不可信宿主 LPA 与 Server 承担；原始生物特征始终不离开 TEE。

---

## 1. 环境与安装（关键操作步骤）

### 1.1 系统要求

Ubuntu 22.04 LTS（x86_64）、4+ CPU、8 GB RAM、20 GB disk，需 AArch64 交叉工具链与 QEMU ARM64。完整规格见 `infrastructure/environment.txt`。

### 1.2 依赖

gcc / g++、CMake（≥3.22）、Python 3 + numpy/pandas/matplotlib、gcc-aarch64-linux-gnu、qemu-user-static、OpenSSL 3.0.13、liboqs 0.15.0。完整清单与版本见 `infrastructure/requirements.txt`，第三方库与许可证见 `infrastructure/THIRD_PARTY.md`。

### 1.3 安装

```bash
bash install.sh
```

`install.sh` 一次性完成：安装系统包 → 安装 Python 依赖 → 编译 OpenSSL / liboqs（native + aarch64）→ 编译 C 核心（native + ARM64）→ 准备各 claim 的 `results/` 目录。幂等可重复执行。

---

## 2. 最快跑通（Quick Start / 端到端 Demo）

```bash
git clone https://github.com/shuijinsan/PQ-ZK-eSIM
cd PQ-ZK-eSIM
bash install.sh
bash artifact/demo/run.sh
```

即可看到最小完整演示：Terminal/LPA → TEE gate → eUICC prover → Backend Server → Verifier，正向合法 proof 输出 **ACCEPT**，负向篡改 proof 输出 **REJECT**（结果来自真实 verifier 密码学计算，非写死文本）。

---

## 3. 仓库结构

```
PQ-ZK-eSIM/
├── artifact/
│   ├── terminal/euicc/   # C 核心：prover / verifier / crypto / lattice / TEE
│   └── demo/             # 端到端 demo（run.sh）
├── claims/               # 5 个论文实验 claim（见第 4 节）
├── infrastructure/       # 环境 / 依赖 / 约束 / 访问说明
├── install.sh            # 一键安装
├── validate.sh           # 结果一致性校验
├── README.txt            # 本文件
├── metadata.toml         # Artifact 元数据
├── license.txt           # 许可证
└── use.txt               # 用途与限制
```

- `artifact/terminal/euicc/`：全部密码学代码（协议、格运算、NTT、Merkle、ML-DSA/ML-KEM、NVRAM）。详见 `artifact/terminal/euicc/README.md`。
- `artifact/demo/`：把 prover/verifier 串成一条命令的冒烟测试。
- `claims/`：每个 claim 一个目录，含 `claim.txt` + `run.sh` + `expected/` + `results/`（见下）。
- `infrastructure/`：环境、依赖、约束的详细说明。

---

## 4. 实验复现（Claims）

### 4.1 Claim 目录结构（各文件意义）

每个 `claims/<claim>/` 目录包含：

| 文件/目录 | 作用 |
|---|---|
| `claim.txt` | 说明该 claim 对应论文哪张 Figure/Table、实验内容、输入、预期输出、运行时间、资源、**Tolerance（误差认定）** |
| `run.sh` | 一键运行脚本，产出 CSV 到 `results/`，**不会覆盖 `expected/`** |
| `expected/` | 参考结果（本仓库记录的 CSV + 论文图） |
| `results/` | `run.sh` 在当前机器上产生的实际结果（用于与 `expected/` 比较） |

### 4.2 全部实验指令

| Claim | 论文 | 实验内容 | 命令 | 预计 |
|---|---|---|---|---|
| claim1_qemu_performance | Figure 5, §7.2 | QEMU ARM64 分相时延，验证 eUICC 无 NTT/高斯 | `bash claims/claim1_qemu_performance/run.sh --quick` | ~2-3 min |
| claim2_security_estimation | Figure 4, §7.1 | Module-SIS 安全估计（外部 lattice-estimator） | 无 run.sh（documented result，需自行安装 lattice-estimator） | — |
| claim3_dos_early_reject | Figure 8, App D | MAC 预过滤提前拒绝（DoS 抗性） | `bash claims/claim3_dos_early_reject/run.sh` | ~1 min |
| claim4_sliding_window | Figure 6, App D | 滑动窗口 MAC 重同步 | `bash claims/claim4_sliding_window/run.sh --quick` | ~1-2 min |
| claim5_sparse_noise | Figure 7, App D | 稀疏噪声注入检测 | `bash claims/claim5_sparse_noise/run.sh --quick` | ~1-2 min |

注：`--quick` 与 `--full` 在当前实现中等价（参数为编译期常量）。claim2 依赖外部 lattice-estimator（未 vendor，固定 commit `d2bf9ca`），故以 documented result 形式提供，不设 run.sh。

### 4.3 结果存放位置

运行 `run.sh` 后，实际结果写入对应 `claims/<claim>/results/`（如 `phase_timing_results.csv`、`dos_results.csv`、`sliding_window_resync_results.csv`、`sparse_noise_attack_results.csv`）。`expected/` 内的参考结果保持不变。

---

## 5. 实验结果与误差认定

运行全部实验后，用一条命令校验结果一致性：

```bash
bash validate.sh            # 校验全部 claim
bash validate.sh claim3_dos_early_reject   # 只校验某个 claim
```

`validate.sh` 内部调用 `validate.py`，将 `results/` 与 `expected/` 逐列比较，规则与各 `claim.txt` 的 **Tolerance** 一致：

| 结果类型 | 认定规则 | 说明 |
|---|---|---|
| key（行标识列） | **精确匹配**（行集合 + 顺序） | 如 `rho`、`(window_size, sync_depth)` |
| 确定性结果 | **严格判定** | `success_rate`（窗口内 1.0 / 窗口外 0.0）、`detection_rate`（ρ≤0.75 → 1.0，ρ=1.0 → 0.0）、`Speedup > 1`、运算计数 |
| 时序结果 | **更快直接通过；更慢 ≤100%（2×）** | `avg_us` / `avg_total_us` 等延迟列 |

**为什么这样认定**（依据论文）：确定性结果来自密码学 / 算法性质，必须严格复现（例如「eUICC 无 NTT」是 code-level 性质，不是时序测量）；时序结果仅用于刻画「工作负载拆分」的可行性剖面，论文明确说明 QEMU 是 *software workload/feasibility profile*、**非真实硬件测量**，且逐机器波动。因此时序采用**非对称容差**：机器更快（延迟更低）是更有利的方向，直接判通过；机器更慢（延迟更高）则允许慢至参考值的 2 倍（即 +100%），超过才判失败。此外 claim1 的 500 次逐次时延抖动过大，只校验「表头 + 行数」，不比较具体 µs。

---

## 6. 实验遵循的规范（依据论文）

- **参数**：与论文 Table 3 完全一致 —— N=256、k=5、m=8、q=8,380,417、κ=35、σ_pub=5000、β_min/max=200,000/260,000、β_∞=35,700、β_L1=7,400,000。
- **claim ↔ 论文映射**：见 §4.2 表格（Figure 4/5/6/7/8 及 §7.1、§7.2、Appendix D）。
- **QEMU 定位**：eUICC 跑在 QEMU ARM64（Cortex-A53）模拟环境，属 *software workload profile*，**不是**真实 TrustZone/eUICC 硬件测量（论文 §7）。
- **eUICC 时延**：Table 4 的 4.2 ms 是 **analytical projection**（基于运算次数 × 周期假设），非 on-card 实测。
- **eUICC 无 NTT / 无高斯**：论文 §7.2 的 code-level 性质 —— eUICC 响应路径仅 `mκN ≈ 7.17×10⁴` 次三元加法，NTT/高斯采样全在 LPA/Server 侧。
- **安全性**：不可伪造性归约到 Module-SIS，辅以 low-density decisional SIS 假设（论文 §6 / Theorem 4）；claim2 的 lattice-estimator 需固定 commit `d2bf9ca` 复现。
- **高斯淹没**：有限 flooding 计算为 illustrative（不实例化渐近 negligible-distance 条件），原型用 Box-Muller 近似（见 §9）。

---

## 7. 协议与安全参数

### 协议概览

PQ-ZK-eSIM 把计算分给三方：

- **TEE** — 生物特征匹配 + 一次性 AuthToken 签发；
- **eUICC** — 仅做稀疏三元加法（无 NTT、无高斯采样）；
- **LPA**（不可信宿主）— 承担全部重格运算（盲加速器）。

服务端四阶段流水线验证：滑动窗口 MAC 预过滤 → Merkle 路径校验 → 去掩码 → 带多范数界的格验证（验证关系 A·z_unmask − T·c_agg = W）。

### 安全参数

| 参数 | 值 | 说明 |
|---|---|---|
| N | 256 | 环维度 |
| K × M | 5 × 8 | 矩阵维度 |
| q | 8,380,417 | 模数（2²³ − 2¹³ + 1）|
| κ | 35 | 挑战权重 |
| σ_pub | 5,000 | 高斯淹没宽度 |
| β_∞ | 35,700 | ℓ∞ 上界 |
| β_final / β_min | 260,000 / 200,000 | ℓ₂ 上 / 下界 |
| β_L1 | 7,400,000 | L₁ 下界 |

### 核心性质

- 抗量子不可伪造性（Module-SIS 归约 + low-density decisional SIS 假设）
- eUICC 无 NTT（仅 mκN ≈ 7.17×10⁴ 次三元加法）
- 生物特征不暴露（TEE 内限定，仅公开 Merkle 根）
- LPA 盲性（HKDF 派生密钥下的 PRF 掩码）
- 服务端视角可模拟性（高斯淹没，Rényi 散度界）
- DoS 抗性（MAC 预过滤提前拒绝）
- 前向保密（每会话 KDF 密钥演进）
- 状态稳健性（滑动窗口 MAC 重同步，原子 NVRAM 写入）

---

## 8. 后端（SM-DP+ Verifier）

ACCEPT / REJECT 来自真实 verifier 密码学计算，非写死文本。

- **demo 内（已跑通，以此为准）**：`artifact/demo/run.sh` 直接在 C 端调用 `euicc/src/pq_zk_esim.c` 的 `PQC_VerifyEngine` 完成验证（MAC 预过滤 → Merkle 路径 → 去掩码 → 范数/格等式），正向 ACCEPT、负向 REJECT，无需外部服务。
- **独立 FastAPI 后端（SM-DP+，可选部署）**：另提供一套网络版后端，`main.py` 的 `verify_engine()` 对应 C 端 `PQC_VerifyEngine`；依赖 FastAPI/uvicorn/SQLAlchemy/PyMySQL/redis、MySQL 8.0 + Redis，监听 TCP 8000，接口 `POST /api/v1/auth/{register,challenge,verify}`，正向 200、负向 403。

后端运行环境、调用关系、正向/负向测试用例详见根目录「SM-DP+ Verifier 调用关系与测试说明.md」。

---

## 9. 限制

完整清单见 `use.txt` 和 `infrastructure/constraints.txt`。核心点：

- eUICC 为 QEMU ARM64 模拟，非真实硬件；
- eUICC latency（Table 4）为 analytical projection；
- TEE/eUICC 为研究原型，非生产 GSMA 认证部署；
- 安全性评估依赖外部 lattice-estimator，未 vendor；
- 高斯淹没采样用 Box-Muller 连续高斯取整近似，非严格离散高斯采样器（论文已说明有限 flooding 计算为 illustrative，不实例化渐近 negligible-distance 条件）。

---

## 10. 故障排查

- 缺依赖：对照 `infrastructure/requirements.txt` 逐项安装。

---

## 11. 许可证

见 `license.txt`（Apache 2.0）和 `infrastructure/THIRD_PARTY.md`。

---

## 12. AE 期间联系人

（待补充联系人）
