"""
卡密验证服务器
FastAPI + SQLite，支持：
- 生成卡密（带有效期天数）
- 验证/激活卡密（绑定机器ID，一卡一机）
- 查询卡密状态
- 管理员重置卡密

运行：
  pip install fastapi uvicorn sqlalchemy pydantic
  python server.py
部署：
  可用 render.com / railway.app 免费托管
"""

import sqlite3
import hashlib
import secrets
import string
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

# ============================================================
# 配置
# ============================================================
DB_PATH = Path(__file__).parent / "keys.db"
ADMIN_KEY = "rf4admin2025"   # 管理员密钥，生成/重置卡密用，部署后请修改！

app = FastAPI(title="俄钓助手卡密验证服务", version="1.0")

api_key_header = APIKeyHeader(name="X-Admin-Key")


# ============================================================
# 数据库
# ============================================================
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_text TEXT UNIQUE NOT NULL,
        key_hash TEXT UNIQUE NOT NULL,
        valid_days INTEGER NOT NULL,
        used INTEGER DEFAULT 0,
        machine_id TEXT DEFAULT NULL,
        activated_at INTEGER DEFAULT NULL,
        created_at INTEGER DEFAULT (strftime('%s','now'))
    )
    """)
    conn.commit()
    conn.close()


init_db()


# ============================================================
# 模型
# ============================================================
class ActivateRequest(BaseModel):
    key: str
    machine_id: str


class GenerateRequest(BaseModel):
    count: int = 1
    valid_days: int = 15


class ResetRequest(BaseModel):
    key: str


# ============================================================
# 工具
# ============================================================
def gen_key() -> str:
    """生成 XXXX-XXXX-XXXX-XXXX 格式卡密"""
    chars = string.ascii_uppercase + string.digits
    return "-".join(
        "".join(secrets.choice(chars) for _ in range(4))
        for _ in range(4)
    )


def check_admin(key: str = Security(api_key_header)):
    if key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="管理员密钥错误")
    return True


# ============================================================
# 接口
# ============================================================

@app.get("/")
def root():
    return {"msg": "俄钓助手卡密验证服务运行中", "version": "1.0"}


@app.post("/activate")
def activate(req: ActivateRequest):
    """
    激活卡密（客户端调用）
    - 卡密格式: XXXX-XXXX-XXXX-XXXX
    - 返回: {ok, valid_days, expire_at, message}
    """
    key = req.key.strip().upper()
    machine_id = req.machine_id.strip()
    key_hash = hashlib.sha256(key.encode()).hexdigest()

    conn = get_db()
    row = conn.execute("SELECT * FROM keys WHERE key_hash = ?", (key_hash,)).fetchone()

    if not row:
        conn.close()
        return {"ok": False, "message": "卡密不存在"}

    if row["used"]:
        # 已激活：检查是否同一台机器
        if row["machine_id"] == machine_id:
            expire_at = row["activated_at"] + row["valid_days"] * 86400
            remaining = max(0, int((expire_at - datetime.now().timestamp()) / 86400))
            conn.close()
            return {
                "ok": True,
                "valid_days": row["valid_days"],
                "expire_at": expire_at,
                "remaining_days": remaining,
                "message": "已激活（同一台机器）"
            }
        else:
            conn.close()
            return {"ok": False, "message": "卡密已被其他设备使用"}

    # 首次激活
    now = int(datetime.now().timestamp())
    conn.execute(
        "UPDATE keys SET used = 1, machine_id = ?, activated_at = ? WHERE key_hash = ?",
        (machine_id, now, key_hash)
    )
    conn.commit()
    conn.close()

    expire_at = now + row["valid_days"] * 86400
    return {
        "ok": True,
        "valid_days": row["valid_days"],
        "expire_at": expire_at,
        "remaining_days": row["valid_days"],
        "message": "激活成功"
    }


@app.post("/generate")
def generate(req: GenerateRequest, _: bool = Depends(check_admin)):
    """
    生成卡密（管理员调用）
    返回卡密列表，需妥善保存（服务端只存哈希）
    """
    results = []
    conn = get_db()
    for _ in range(req.count):
        key = gen_key()
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        try:
            conn.execute(
                "INSERT INTO keys (key_text, key_hash, valid_days) VALUES (?, ?, ?)",
                (key, key_hash, req.valid_days)
            )
            results.append({"key": key, "valid_days": req.valid_days})
        except sqlite3.IntegrityError:
            pass  # 极小概率碰撞，重试
    conn.commit()
    conn.close()
    return {"ok": True, "keys": results}


@app.post("/reset")
def reset(req: ResetRequest, _: bool = Depends(check_admin)):
    """
    重置卡密（管理员调用）
    清除 used / machine_id / activated_at，卡密可重新使用
    """
    key = req.key.strip().upper()
    key_hash = hashlib.sha256(key.encode()).hexdigest()

    conn = get_db()
    r = conn.execute("SELECT id FROM keys WHERE key_hash = ?", (key_hash,)).fetchone()
    if not r:
        conn.close()
        raise HTTPException(status_code=404, detail="卡密不存在")
    conn.execute(
        "UPDATE keys SET used = 0, machine_id = NULL, activated_at = NULL WHERE key_hash = ?",
        (key_hash,)
    )
    conn.commit()
    conn.close()
    return {"ok": True, "message": "卡密已重置"}


@app.get("/stats")
def stats(_: bool = Depends(check_admin)):
    """统计信息（管理员调用）"""
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
    used = conn.execute("SELECT COUNT(*) FROM keys WHERE used = 1").fetchone()[0]
    unused = total - used
    conn.close()
    return {"total": total, "used": used, "unused": unused}


if __name__ == "__main__":
    import uvicorn
    # 本地测试用，生产部署请用 render.com 等
    uvicorn.run(app, host="0.0.0.0", port=8000)
