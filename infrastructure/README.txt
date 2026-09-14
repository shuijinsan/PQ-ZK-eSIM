# infrastructure/ 目录说明

本目录描述 Artifact 的运行环境与依赖。

- requirements.txt  依赖清单（reviewer 需安装的软件与版本）
- environment.txt   canonical 可复现环境规格
- constraints.txt   约束与限制（如实说明，不隐藏）
- access.txt        获取 / 安装 / 运行方式
- THIRD_PARTY.md    第三方库与许可证（勿改动）

## 后端依赖

后端（SM-DP+ Verifier）环境见根目录「SM-DP+ Verifier 调用关系与测试说明.md」，依赖已填入 `requirements.txt` 的「后端」部分：
- Python ≥ 3.9（venv）
- FastAPI / uvicorn / SQLAlchemy / PyMySQL / redis / cryptography
- MySQL 8.0（localhost:3306）、Redis-server（localhost:6379）
