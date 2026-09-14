# TEE 模拟方式

TEE（Trusted Execution Environment）在本 Artifact 中是**进程内 C 库模拟**，不是真实硬件隔离环境（如 TrustZone）。

## 核心文件

- `../euicc/src/tee/pqzk_merkle.c` + `../euicc/include/pqzk_merkle.h` — 生物特征 Merkle 树
- `../euicc/src/pq_zk_esim.c` — `TEE_GenerateAuthToken`（Phase 3）+ `PQC_ComputeZ_and_Mask` 内的 AuthToken 校验（Phase 4）

## 协议/密码学逻辑

详见同目录 `TEE_logic.md`。

## 启动方式

无独立 TEE 进程。TEE 门控由 `pqzkesim_app --auth` 内部调用 `TEE_GenerateAuthToken` 完成，不单独启动。

## 说明（措辞红线）

这是**研究原型/模型**，不是生产 GSMA 认证的 TEE 部署。
