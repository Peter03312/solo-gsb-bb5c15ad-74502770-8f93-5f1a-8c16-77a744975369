"""运行配置。

全部配置均支持通过环境变量覆盖，便于在 Docker / Compose 中调整。
"""
from __future__ import annotations

import os
from dataclasses import dataclass


def _as_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


@dataclass
class Settings:
    # SQLite 数据库文件路径，:memory: 仅用于测试
    db_path: str = os.getenv("AUDIT_DB_PATH", os.path.join(os.getcwd(), "audit.db"))
    # 写锁等待秒数（busy_timeout 毫秒数 = 该值 * 1000）
    db_timeout: int = _as_int("AUDIT_DB_TIMEOUT", 10)
    # 核验包签名 RSA 密钥位数（RS256）；生产保持 2048，测试可调小加速
    signing_key_bits: int = _as_int("AUDIT_SIGNING_KEY_BITS", 2048)

    @property
    def busy_timeout_ms(self) -> int:
        return self.db_timeout * 1000


settings = Settings()
