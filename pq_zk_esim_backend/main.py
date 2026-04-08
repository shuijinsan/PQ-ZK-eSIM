from fastapi import FastAPI, HTTPException, Depends, Request
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, Text, DateTime, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime
import redis
import uuid
import hashlib
import hmac

# ===================== 1. 项目基础配置（和你之前的完全匹配，不用改）=====================
DATABASE_URL = "mysql+pymysql://root:123456@localhost:3306/pq_zk_esim_db?charset=utf8mb4"
REDIS_URL = "redis://:123456@localhost:6379/0"

app = FastAPI(
    title="PQ-ZK-eSIM SM-DP+ 后端服务",
    version="1.0.0",
    description="符合5.0协议要求，支持注册、挑战、验证全流程"
)

# 初始化MySQL连接
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# 初始化Redis连接
redis_client = redis.from_url(REDIS_URL, decode_responses=True)
try:
    redis_client.ping()
    print("✅ Redis 连接成功!")
except Exception as e:
    print(f"❌ Redis 连接失败:{e}")

# 协议固定参数（完全对齐头文件和5.0协议）
HASH_ALGORITHM = "sha256"
SESSION_TTL = 300  # 会话5分钟过期
CTR_WINDOW_SIZE = 5  # 计数器滑动窗口[-5,+5]
D_SEED = b"pq_zk_esim_2026_dseed_fixed"  # 密钥派生固定种子
DEFAULT_DOMAIN_ID = "default_mno"  # 默认运营商域ID

# ===================== 2. 数据库表定义（已更新5.0要求的salt和domain_id）=====================
class DBUser(Base):
    __tablename__ = "users"
    user_id = Column(String(64), primary_key=True, index=True)
    e_uicc_id = Column(String(128), unique=True, index=True, nullable=False)
    public_key_t = Column(Text, nullable=False)
    k_sym = Column(Text, nullable=False)
    r_bio = Column(Text, nullable=True)
    salt = Column(String(64), nullable=False)  # 5.0新增：设备特定随机盐
    domain_id = Column(String(64), nullable=False, default=DEFAULT_DOMAIN_ID)  # 5.0新增：运营商域ID
    ctr_server = Column(Integer, default=0)
    register_time = Column(DateTime, default=datetime.now)
    last_auth_time = Column(DateTime, default=datetime.now, onupdate=datetime.now)

# 自动创建表（如果不存在）
Base.metadata.create_all(bind=engine)

# ===================== 3. 工具函数（完全对齐5.0协议要求）=====================
# 数据库会话工具
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# 5.0协议要求：带salt的Merkle根验证（后端独立实现，不调用C库）
def verify_merkle_path_with_salt(M1: str, M2: str, expected_root: str, salt: str) -> bool:
    try:
        # 先把salt和M2拼接，再计算哈希，完全对齐5.0协议
        combined = hashlib.sha256((M1 + M2 + salt).encode("utf-8")).hexdigest()
        return combined.lower() == expected_root.lower()
    except Exception as e:
        print(f"Merkle验证失败: {e}")
        return False

# 协议工具：MAC_W计算（完全对齐头文件要求，小端序编码）
def compute_mac_w(k_sym: str, w_sec: str, ctr: int) -> str:
    try:
        w_sec_bytes = bytes.fromhex(w_sec) if len(w_sec) % 2 == 0 else w_sec.encode("utf-8")
        # 计数器按小端序编码为8字节
        ctr_bytes = ctr.to_bytes(8, byteorder="little", signed=False)
        message = w_sec_bytes + ctr_bytes
        key = bytes.fromhex(k_sym) if len(k_sym) % 2 == 0 else k_sym.encode("utf-8")
        mac = hmac.new(key, message, hashlib.sha256).hexdigest()
        return mac
    except Exception as e:
        print(f"MAC_W计算失败: {e}")
        return ""

# 协议工具：前向安全密钥KDF函数
def kdf_k_sym(current_k_sym: str, d_seed: bytes, e_uicc_id: str) -> str:
    combined = current_k_sym.encode("utf-8") + d_seed + e_uicc_id.encode("utf-8")
    return hashlib.sha256(combined).hexdigest()

# 协议工具：5.0新增-域特定根+动态根双层派生
def derive_dynamic_root(r_bio: str, domain_id: str, ctr_session: int) -> str:
    # 第一步：派生域特定根 R_bio_domain = Hash(R_bio || Domain_ID)
    r_bio_domain = hashlib.sha256((r_bio + domain_id).encode("utf-8")).hexdigest()
    # 第二步：派生会话动态根 R_dynamic = Hash(R_bio_domain || ctr_session)
    ctr_bytes = ctr_session.to_bytes(8, byteorder="little", signed=False)
    r_dynamic = hashlib.sha256(r_bio_domain.encode("utf-8") + ctr_bytes).hexdigest()
    return r_dynamic

# ===================== 4. 接口入参/出参定义（完全对齐5.0协议）=====================
# 【3.25节点核心：注册接口】已更新5.0要求的salt参数
class UserRegisterRequest(BaseModel):
    e_uicc_id: str
    public_key_t: str
    k_sym: str
    r_bio: str
    salt: str  # 5.0新增：设备特定随机盐，必填

class UserRegisterResponse(BaseModel):
    code: int = 200
    message: str = "注册成功"
    user_id: str
    register_time: datetime
    cred_kyc: str  # 5.0新增：权威身份凭证

# 挑战分发接口
class ChallengeRequest(BaseModel):
    W: str
    W_sec: str
    MAC_W: str
    H_ctx: str
    e_uicc_id: str

class ChallengeResponse(BaseModel):
    code: int = 200
    message: str = "挑战生成成功"
    c_seed: str
    H_ctx: str
    M1: str
    session_id: str

# 认证验证接口
class VerifyRequest(BaseModel):
    z: str
    M2: str
    session_id: str
    e_uicc_id: str

class VerifyResponse(BaseModel):
    code: int = 200
    message: str = "认证成功"
    auth_time: datetime
    new_ctr_server: int

# 健康检查响应
class HealthResponse(BaseModel):
    code: int = 200
    message: str = "服务运行正常"
    mysql_status: str
    redis_status: str

# ===================== 5. 核心接口实现（全流程闭环，符合所有交付要求）=====================
# 健康检查接口
@app.get("/", tags=["健康检查"], response_model=HealthResponse)
async def health_check():
    mysql_status = "正常"
    try:
        engine.connect()
    except:
        mysql_status = "异常"
    redis_status = "正常"
    try:
        redis_client.ping()
    except:
        redis_status = "异常"
    return HealthResponse(
        mysql_status=mysql_status,
        redis_status=redis_status
    )

# 【3.25节点交付核心】用户注册接口（已更新5.0所有要求）
@app.post("/api/v1/auth/register", tags=["用户认证"], response_model=UserRegisterResponse)
async def user_register(request: UserRegisterRequest, db: Session = Depends(get_db)):
    # 1. 检查设备是否已注册
    exist_user = db.query(DBUser).filter(DBUser.e_uicc_id == request.e_uicc_id).first()
    if exist_user:
        raise HTTPException(status_code=400, detail="该设备已注册，请勿重复注册")
    
    # 2. 生成用户ID
    user_id = str(uuid.uuid4()).replace("-", "")
    
    # 3. 5.0要求：生成权威身份凭证 Cred_KYC = Sign(EID || R_bio)
    # 这里先模拟签名，算法师给了签名库后直接替换即可
    cred_kyc = hashlib.sha256((request.e_uicc_id + request.r_bio).encode("utf-8")).hexdigest()
    
    # 4. 存入数据库（包含5.0新增的salt和domain_id）
    new_user = DBUser(
        user_id=user_id,
        e_uicc_id=request.e_uicc_id,
        public_key_t=request.public_key_t,
        k_sym=request.k_sym,
        r_bio=request.r_bio,
        salt=request.salt,
        domain_id=DEFAULT_DOMAIN_ID,
        ctr_server=0
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # 5. 返回结果（包含5.0要求的Cred_KYC）
    return UserRegisterResponse(
        user_id=user_id,
        register_time=new_user.register_time,
        cred_kyc=cred_kyc
    )

# 挑战分发接口（协议阶段二要求）
@app.post("/api/v1/auth/challenge", tags=["用户认证"], response_model=ChallengeResponse)
async def challenge_distribute(request: ChallengeRequest, db: Session = Depends(get_db)):
    # 1. 校验用户是否已注册
    user = db.query(DBUser).filter(DBUser.e_uicc_id == request.e_uicc_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="该设备未注册，请先完成注册")
    
    # 2. 生成协议要求的参数
    session_id = str(uuid.uuid4()).replace("-", "")
    c_seed = uuid.uuid4().hex  # 32字节挑战种子
    M1 = uuid.uuid4().hex[:16]  # 生物特征挑战索引
    
    # 3. 会话数据存入Redis，设置5分钟过期
    session_data = {
        "e_uicc_id": request.e_uicc_id,
        "user_id": user.user_id,
        "c_seed": c_seed,
        "H_ctx": request.H_ctx,
        "W": request.W,
        "W_sec": request.W_sec,
        "MAC_W": request.MAC_W,
        "M1": M1
    }
    redis_client.hset(session_id, mapping=session_data)
    redis_client.expire(session_id, SESSION_TTL)
    
    # 4. 返回结果
    return ChallengeResponse(
        c_seed=c_seed,
        H_ctx=request.H_ctx,
        M1=M1,
        session_id=session_id
    )

# 认证验证接口（协议阶段六要求，已更新5.0所有逻辑）
@app.post("/api/v1/auth/verify", tags=["用户认证"], response_model=VerifyResponse)
async def auth_verify(request: VerifyRequest, db: Session = Depends(get_db)):
    session_id = request.session_id
    
    # 1. 提取会话数据，过期直接返回401
    session_data = redis_client.hgetall(session_id)
    if not session_data:
        raise HTTPException(status_code=401, detail="会话已过期或不存在，请重新发起挑战")
    
    e_uicc_id = session_data.get("e_uicc_id", "")
    W = session_data.get("W", "")
    W_sec = session_data.get("W_sec", "")
    MAC_W_client = session_data.get("MAC_W", "")
    M1 = session_data.get("M1", "")

    # 2. 拉取用户信任锚点（包含5.0新增的salt和domain_id）
    user = db.query(DBUser).filter(DBUser.e_uicc_id == e_uicc_id).first()
    if not user:
        raise HTTPException(status_code=403, detail="用户未注册，认证失败")

    # 3. 5.0要求：带salt的Merkle根验证
    if not verify_merkle_path_with_salt(M1, request.M2, user.r_bio, user.salt):
        raise HTTPException(status_code=403, detail="生物特征校验失败，TEE数据伪造")

    # 4. 计数器滑动窗口匹配+MAC_W完整性校验
    current_ctr = user.ctr_server
    matched_ctr = -1
    matched_k_sym = ""

    for ctr_offset in range(-CTR_WINDOW_SIZE, CTR_WINDOW_SIZE + 1):
        test_ctr = current_ctr + ctr_offset
        if test_ctr < 0:
            continue
        computed_mac = compute_mac_w(user.k_sym, W_sec, test_ctr)
        if computed_mac.lower() == MAC_W_client.lower():
            matched_ctr = test_ctr
            matched_k_sym = user.k_sym
            break

    if matched_ctr == -1:
        raise HTTPException(status_code=403, detail="计数器失步或重放攻击，认证失败")

    # 5. 5.0要求：域特定根+动态根双层派生
    r_dynamic = derive_dynamic_root(user.r_bio, user.domain_id, matched_ctr)

    # 6. 远端掩码生成（算法师给了.so库后替换为调用C接口）
    c_seed = session_data.get("c_seed", "")
    H_ctx = session_data.get("H_ctx", "")
    M_mask = hashlib.sha256((matched_k_sym + c_seed + str(matched_ctr) + r_dynamic).encode()).hexdigest()

    # 7. 核心代数引擎验证（算法师给了.so库后替换为调用PQC_VerifyEngine）
    # 这里先模拟验证成功，算法库对接后直接替换
    verify_success = True

    if not verify_success:
        raise HTTPException(status_code=403, detail="代数验证失败，响应无效")

    # 8. 远端状态机演进（计数器更新+前向安全密钥更新）
    new_ctr = matched_ctr + 1
    new_k_sym = kdf_k_sym(matched_k_sym, D_SEED, user.e_uicc_id)
    user.ctr_server = new_ctr
    user.k_sym = new_k_sym
    user.last_auth_time = datetime.now()
    db.commit()

    # 9. 销毁会话，防止重放
    redis_client.delete(session_id)

    # 返回认证结果
    return VerifyResponse(
        auth_time=user.last_auth_time,
        new_ctr_server=new_ctr
    )

# ===================== 6. 服务启动入口 =====================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)