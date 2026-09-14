# PQ‑ZK‑eSIM SM‑DP\+ Verifier调用关系与测试说明

# 3 号\(deliverable\.md\)

> PQ‑ZK‑eSIM SM‑DP\+ Verifier 调用关系与测试说明
> 说明：本交付不修改后端代码；ACCEPT / REJECT 结果来自真实 verifier 密码学计算，非固定写死文本。
> 
> 

## 后端运行环境信息

### Python 版本

- 运行环境：Python ≥ 3\.9（服务器 Ubuntu 24\.04 系统 Python3）

- 运行模式：Python venv 虚拟环境隔离

### Python 依赖包（pip list）

|Package|Version|
|---|---|
|annotated‑types|0\.8\.0|
|anyio|4\.15\.1|
|click|8\.5\.0|
|cryptography|50\.0\.1|
|fastapi|0\.115\.0|
|greenlet|3\.5\.5|
|h11|0\.16\.0|
|idna|3\.19|
|pydantic|2\.9\.2|
|pydantic‑core|2\.23\.4|
|PyMySQL|1\.1\.1|
|python‑multipart|0\.0\.9|
|redis|5\.0\.1|
|SQLAlchemy|2\.0\.36|
|starlette|0\.38\.6|
|typing\_extensions|4\.16\.0|
|uvicorn|0\.30\.6|

### 外部系统服务（runtime）

1. **MySQL 8\.0**

    - 地址：`localhost:3306`

    - 账号：root / 123456

    - 数据库名：`pq_zk_esim_db`

    - 用途：持久化 eSIM 设备服务端状态（users 表）

2. **Redis‑server**

    - 地址：`localhost:6379`，无密码

    - 用途：存储认证临时会话 session，会话 TTL = 300 秒

### 端口与网络要求

- 应用监听端口：**8000**，监听地址 `0.0.0.0`

- 外部访问地址：`http://43.157.25.142:8000`

- 防火墙 / 安全组规则：**入方向放行 TCP 8000 端口**

- 内部访问：后端需要本机可连通 MySQL:3306、Redis:6379

- 接口文档地址：`http://43.157.25.142:8000/docs`

### 后端启动命令

```bash
# 进入项目目录、激活虚拟环境
cd ~/pq_zk_esim_backend
source venv/bin/activate

# 后台启动服务
nohup uvicorn main:app --host 0.0.0.0 --port 8000 > server.log 2>&1 &

# 查看进程
ps aux | grep uvicorn

# 实时查看运行日志
tail -f server.log
```

## Verifier 调用关系说明

|项目|位置说明|
|---|---|
|Verifier entry point|Python 后端：`main.py` 函数 `verify_engine()`<br>对应 C 终端：`euicc/src/pq_zk_esim.c` 的 `PQC_VerifyEngine`|
|Verification function|`verify_engine(W, z, public_key_t, c_seed, k_sym, ctr, r_dynamic)`|
|Server‑side state|MySQL 数据库 `users` 表持久化设备状态：`e_uicc_id`、`public_key_t`、`k_sym`、`ctr_server`、`r_bio`、`salt`、`d_seed`、`n_leaves`<br>Redis 保存本次认证临时会话：`session_id` 作为 key，存储 `W`、`W_sec`、`MAC_W`、`c_seed`、`M1`、`e_uicc_id`，会话 TTL=300s<br>对应 C 终端：`euicc/app/main.c` 中 `mode_auth` 读取 `registration_data.bin`|
|ACCEPT / REJECT 结果来源|`verify_engine()` 返回值：`(True, "")` 代表验证通过；`(False, reason)` 代表验证失败；再叠加前置 Merkle、MAC‑W、计数器校验，共同决定 ACCEPT / REJECT|

### 完整调用链路

```Plain Text
终端请求 → POST /api/v1/auth/verify
    ↓
接口 auth_verify()
    ├─读取 Redis session 会话状态
    ├─MySQL 读取设备 users 表服务端状态
    ├─Merkle路径校验 verify_merkle_path()
    ├─MAC‑W + 计数器滑动窗口校验 compute_mac_w()
    ├─derive_dynamic_root() 生成 R_dynamic
    └─调用 verifier：verify_engine()
        ├─范数检查(L∞ / L2 / L1)
        ├─格等式 W' = A·z_unmasked − T·c mod q
        └─比对 W' == W
    ↓
verify_engine 返回 True → ACCEPT：更新DB计数器与k_sym，销毁Redis会话，HTTP返回200
verify_engine 返回 False / 前置校验失败 → REJECT：抛出HTTPException，返回403错误
```

### ACCEPT 条件

- Merkle 路径校验通过

- MAC‑W 与计数器滑动窗口匹配成功

- `verify_engine()` 内部范数检查全部通过

- 格等式 `W' == W` 比对成功

> 全部满足后更新服务端状态，销毁会话，返回认证成功。
> 
> 

### REJECT 条件（任意一项触发即拒绝）

- 会话不存在或过期

- Merkle 路径校验失败：`生物特征校验失败，TEE数据伪造`

- MAC‑W 校验失败 / 计数器失步重放：`计数器失步或重放攻击，认证失败`

- verify\_engine 内部失败：`norm_inf / norm_l2 / norm_l1 / w_mismatch / exception`，对外返回 `代数验证失败：{reason}`

## 测试用例

### Positive 正向测试

> 用例描述：输入合法 proof 与合法会话，期望输出 ACCEPT。
> 
> 

**前置依赖**

1. 后端服务正常运行：`http://43.157.25.142:8000`，MySQL、Redis 服务正常。

2. 终端生成合法注册参数：`e_uicc_id`、`public_key_t`、`k_sym`、`r_bio`、`salt`、`n_leaves`。

3. 终端本地协议计算产出合法：`W`、`W_sec`、`MAC_W`、`H_ctx`，后续产出合法证明 `z`、`M2`。

**操作步骤**

1. 调用 `POST /api/v1/auth/register`，传入终端合法设备参数完成注册。

2. 调用 `POST /api/v1/auth/challenge`，传入 `e_uicc_id` 及终端生成参数，获取返回值 `session_id`、`c_seed`、`M1`。

3. 终端本地基于 `c_seed`、`M1` 计算合法证明 `z`、`M2`。

4. 调用 `POST /api/v1/auth/verify`，传入参数 `z`、`M2`、`session_id`、`e_uicc_id`。

**期望 HTTP 响应（200 OK）**

```json
{
  "code": 200,
  "message": "认证成功",
  "auth_time": "2026‑09‑14Txx:xx:xx",
  "new_ctr_server": 1
}
```

**后端日志现象**

- 无 Traceback 异常堆栈

- 数据库更新 `ctr_server`、`k_sym`

- Redis 删除本次 `session_id`

---

### Negative 负向测试

> 用例描述：使用篡改后的 proof，其余参数保持合法，期望输出 REJECT。
> 
> 

**前置依赖**
同正向测试，已完成注册、challenge，拿到合法 `session_id`。

**操作步骤**

1. 执行注册、challenge 流程，拿到合法 `session_id`。

2. 终端生成原始合法 `z`，人为篡改 `z` 的若干字节得到篡改后 `z_bad`。

3. 调用 `POST /api/v1/auth/verify`，入参使用篡改后的 `z_bad`，`M2`、`session_id`、`e_uicc_id` 保持不变。

**期望 HTTP 响应（403 Forbidden）**

```json
{
  "detail": "代数验证失败：w_mismatch"
}
```

**后端日志现象**

- 打印代数验证相关异常信息

- HTTP 403 返回，数据库状态不更新，会话不会销毁（会话等待 TTL 自动过期）

> 其他可复现 REJECT 场景：篡改 M2，返回 `生物特征校验失败，TEE数据伪造`。
> 
> 

## demo/\[run\.sh\]\(run\.sh\) 集成指引（交付给 2 号同学）

> 不修改后端源码，通过 HTTP 接口完成自动化测试；判断依据来自接口真实返回，禁止硬编码固定输出字符串。
> 
> 

1. 脚本环境需要安装 `curl`；后端服务需要预先启动完成。

2. Positive 测试脚本逻辑

    - curl 调用 `/api/v1/auth/register` 完成设备注册

    - curl 调用 `/api/v1/auth/challenge` 获取 `session_id`

    - 调用本地终端二进制生成合法 `z`、`M2`

    - curl 调用 `/api/v1/auth/verify`；HTTP 返回码等于 200 则判定 Positive 测试 PASS。

3. Negative 测试脚本逻辑

    - 复用 challenge 得到的合法 `session_id`

    - 对终端输出的 `z` 做人为字节篡改

    - curl 调用 `/api/v1/auth/verify`；HTTP 返回码等于 403 且 detail 包含`代数验证失败`，判定 Negative 测试 PASS。

4. reviewer 也可以直接访问 swagger 页面 `http://43.157.25.142:8000/docs`，手动复现两组测试。

