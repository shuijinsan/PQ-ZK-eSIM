# PQ-ZK-eSIM — Artifact Evaluation

Post-quantum zero-knowledge eSIM authentication protocol.
本仓库是 ACSAC 2026 Artifact Evaluation 的提交物，供 reviewer 独立安装、运行并复现论文主要实验结果。

## 第一屏（Quick Start）

```bash
git clone https://github.com/shuijinsan/PQ-ZK-eSIM
cd PQ-ZK-eSIM
bash install.sh
bash artifact/demo/run.sh
```

即可看到最小完整演示（Terminal/LPA → TEE gate → eUICC prover → Backend Server → Verifier → ACCEPT）。

## Artifact 概览

PQ-ZK-eSIM 把抗量子认证的计算负担从 eUICC 卸载到 LPA/Server：eUICC 只做稀疏三元加法，NTT 和离散高斯采样由 LPA/Server 承担。本 Artifact 提供：

- C 核心（prover/verifier/crypto/lattice/TEE），可在原生 x86 和 QEMU ARM64 编译运行；
- 6 个 claim（对应论文 Figure 5/6/4/7/8/9 及 Table 4）；
- 端到端 demo（含真实 ACCEPT/REJECT）。

## 协议概览

PQ-ZK-eSIM 是格基零知识认证协议，把计算分给三方：

- **TEE** — 生物特征匹配 + 一次性 AuthToken 签发；
- **eUICC** — 仅做稀疏三元加法（无 NTT、无高斯采样）；
- **LPA**（不可信宿主）— 承担全部重格运算（盲加速器）。

服务端通过四阶段流水线验证：滑动窗口 MAC 预过滤 → Merkle 路径校验 → 去掩码 → 带多范数界的格验证（验证关系 A·z_unmask − T·c_agg = W）。QEMU 模拟加解析投影确认工作负载拆分，eUICC 在线密码延迟投影约 4.2 ms（NIST Level 1）。

## 安全参数

| 参数 | 值 | 说明 |
|---|---|---|
| N | 256 | 环维度 |
| K × M | 5 × 8 | 矩阵维度 |
| q | 8,380,417 | 模数（2²³ − 2¹³ + 1）|
| κ | 35 | 挑战权重 |
| σ_pub | 5,000 | 高斯淹没宽度 |
| β_inf | 35,700 | y_pub 系数截断界 |
| β_final / β_min | 260,000 / 200,000 | ℓ₂ 上 / 下界 |
| β_L1 | 7,400,000 | L₁ 下界 |

## 核心性质

- 抗量子不可伪造性（Module-SIS 归约）
- eUICC 无 NTT（仅 mκN ≈ 7.17×10⁴ 次三元加法）
- 生物特征不暴露（TEE 内限定，仅公开 Merkle 根）
- LPA 盲性（HKDF 派生密钥下的 PRF 掩码）
- 服务端视角可模拟性（高斯淹没，Rényi 散度界）
- DoS 抗性（MAC 预过滤提前拒绝）
- 前向保密（每会话 KDF 密钥演进）
- 状态稳健性（滑动窗口 MAC 重同步，原子 NVRAM 写入）

## 目录结构

```
PQ-ZK-eSIM/
├── artifact/
│   ├── terminal/   # 终端/LPA/eUICC/TEE 环境 + C 核心
│   └── demo/       # 端到端 demo
├── claims/         # 6 个论文实验 claim（claim.txt + run.sh + expected/ + results/）
├── infrastructure/ # 依赖/环境/约束说明
├── install.sh      # 一键安装
├── README.txt      # 本文件
├── metadata.toml   # 元数据
├── license.txt     # 许可证
└── use.txt         # 用途与限制
```

## 系统要求

见 `infrastructure/environment.txt`：Ubuntu 22.04 LTS（x86_64）、4+ CPU、8 GB RAM、20 GB disk、AArch64 交叉工具链、QEMU ARM64。

## 安装方法

```bash
bash install.sh
```

依赖清单见 `infrastructure/requirements.txt`，第三方库与许可证见 `infrastructure/THIRD_PARTY.md`。

## Claims 运行命令

| Claim | 命令 | 预计时间 |
|---|---|---|
| claim1_qemu_performance | `bash claims/claim1_qemu_performance/run.sh --quick` | ~2-3 min |
| claim2_euicc_workload | `bash claims/claim2_euicc_workload/run.sh` | ~1-2 min |
| claim3_euicc_projection | （analytical projection，无 run.sh） | — |
| claim4_security_estimation | （外部 lattice-estimator，documented result） | — |
| claim5_desync_dos | `bash claims/claim5_desync_dos/run.sh --quick` | ~1-2 min |
| claim6_sparse_noise | `bash claims/claim6_sparse_noise/run.sh --quick` | ~1-2 min |

结果校验：`bash validate.sh`

## Expected outputs

每个 claim 的 `expected/` 保存参考结果（CSV + 论文图），实际运行结果写入同目录 `results/`，`run.sh` 不会覆盖 expected。

## Resource requirements / runtime

见 `metadata.toml` 中各 claim 的 runtime 与 resource 字段。

## Limitations

见 `use.txt` 和 `infrastructure/constraints.txt`。核心点：

- eUICC 为 QEMU ARM64 模拟，非真实硬件；
- eUICC latency（Table 4）为 analytical projection；
- TEE/eUICC 为研究原型，非生产 GSMA 认证部署；
- 安全性评估依赖外部 lattice-estimator，未 vendor。

## Troubleshooting

- 缺依赖：对照 `infrastructure/requirements.txt` 逐项安装。
- claim2 需要 Valgrind >= 3.20；如未装，其余 claim 不受影响。

## License

见 `license.txt`（Apache 2.0）和 `infrastructure/THIRD_PARTY.md`。

## AE 期间联系人

（待补充联系人）
