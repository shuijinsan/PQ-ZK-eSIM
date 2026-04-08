# PQ-ZK-eSIM SM-DP+ 后端服务

3.25节点交付版，包含完整的注册、挑战、验证全流程接口。

---

## 开发环境

- 操作系统：Ubuntu 24.04 LTS  
- 开发语言：Python 3.12  
- 框架：FastAPI  
- 数据库：MySQL 8.0  
- 缓存：Redis 7.0  

---

## 快速启动

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 启动服务

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

接口文档地址：  
http://127.0.0.1:8000/docs

---

## 核心接口

| 接口地址 | 方法 | 说明 |
|----------|------|------|
| / | GET | 服务健康检查 |
| /api/v1/auth/register | POST | 用户注册接口（3.25 节点核心） |
| /api/v1/auth/challenge | POST | 挑战分发接口 |
| /api/v1/auth/verify | POST | 认证验证接口 |