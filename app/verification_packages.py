"""证书核验包：本地签名密钥管理、出具可携带核验包与接收方核验。

- 签名密钥全部落库（表 signing_keys）：任意时刻至多一行 active；
  轮换把旧行置 retired 但公钥（及私钥）永久保留，重启后旧包仍可验。
- 出具（issue）：只读复用已签发证书的标识/版本/结论/签发时间与其**不可变快照
  摘要**，用当前 active 私钥做 RS256 签名；不修改证书与快照，不落任何记录。
- 核验（verify，只读）：
  1) 未知密钥 / 验签失败 -> 422（签名不可信）；
  2) 无对应证书 -> 404；
  3) 包内快照摘要与库中该证现有快照摘要不符（快照被改/包被伪造）-> 422；
  4) 包内证书标识字段与库中内容不一致 -> 422；
  通过后再回答“该证书当前是否仍为所属窗口最新未撤销版本”：
  已撤销或被新版本替代只作状态说明（可信历史包不等于当前可用），不改业务状态。
"""
from __future__ import annotations

import base64
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import HTTPException, status

from .config import settings
from .models import VERDICT_LABELS_ZH
from .services import certificate_to_dict
from . import signing

DEFAULT_ISSUER = "museum-audit-service"
KEY_ACTIVE = "active"
KEY_RETIRED = "retired"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# ------------------------------------------------------------ 签名密钥

def _signing_key_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "key_id": row["key_id"],
        "status": row["status"],
        "algorithm": row["algorithm"],
        "public_key_pem": row["public_key_pem"],
        "rotate_reason": row["rotate_reason"],
        "created_at": row["created_at"],
    }


def list_signing_keys(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """全部签名密钥（当前 + 历史），按生成顺序升序。"""
    rows = conn.execute(
        "SELECT * FROM signing_keys ORDER BY id ASC"
    ).fetchall()
    return [_signing_key_to_dict(r) for r in rows]


def _get_active_key_row(conn: sqlite3.Connection) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM signing_keys WHERE status=? ORDER BY id DESC LIMIT 1",
        (KEY_ACTIVE,),
    ).fetchone()


def _insert_generated_active_key(conn: sqlite3.Connection, reason: str) -> sqlite3.Row:
    """生成一把新 RSA 密钥并落为 active（调用方须已持事务）。"""
    key = signing.generate_rsa_key(settings.signing_key_bits)
    priv_pem = signing.private_key_pem(key)
    pub_pem = signing.public_key_pem(key["n"], key["e"])
    key_id = signing.public_key_fingerprint(key["n"], key["e"])
    created_at = _utc_now_iso()
    conn.execute(
        """
        INSERT INTO signing_keys (key_id, status, public_key_pem, private_key_pem,
                                  algorithm, rotate_reason, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (key_id, KEY_ACTIVE, pub_pem, priv_pem,
         signing.SIGNATURE_ALG, reason, created_at),
    )
    return conn.execute(
        "SELECT * FROM signing_keys WHERE key_id=?", (key_id,)
    ).fetchone()


def ensure_active_signing_key(conn: sqlite3.Connection) -> None:
    """库内无 active 签名密钥时生成首把（写事务内调用，幂等）。

    正常流程中首把密钥在首次出具核验包（或馆员显式轮换）时按需生成；
    此函数保留给需要在出具前显式预热密钥的调用方。
    """
    if _get_active_key_row(conn) is None:
        _insert_generated_active_key(conn, "服务初始化：首次生成核验包签名密钥")


def rotate_signing_key(
    conn: sqlite3.Connection, reason: Optional[str]
) -> tuple[str, dict[str, Any], list[str]]:
    """在本地轮换签名密钥，返回 (effect, 新密钥dict, 被退役旧密钥id列表)。

    新包此后用新密钥签名；旧密钥置 retired 且公钥/私钥保留，
    历史核验包仍可凭旧公钥核验（重启后一致）。
    """
    old_rows = conn.execute(
        "SELECT * FROM signing_keys WHERE status=?", (KEY_ACTIVE,)
    ).fetchall()
    effect = "rotated" if old_rows else "initialized"
    if old_rows:
        conn.execute(
            "UPDATE signing_keys SET status=? WHERE status=?",
            (KEY_RETIRED, KEY_ACTIVE),
        )
    new_row = _insert_generated_active_key(
        conn, reason or ("馆员本地轮换签名密钥" if old_rows else "馆员初始化签名密钥"))
    return effect, _signing_key_to_dict(new_row), [r["key_id"] for r in old_rows]


# ------------------------------------------------------------ 出具核验包

def _unsigned_package_fields(cert: dict[str, Any], key_row: sqlite3.Row) -> dict[str, Any]:
    """除 signature 外的全部包字段（固定键集合，签名覆盖这些字段）。"""
    return {
        "package_type": "certificate-verification-package",
        "package_version": 1,
        "certificate_id": cert["id"],
        "window_id": cert["window_id"],
        "version": cert["version"],
        "verdict": cert["verdict"],
        "verdict_label_zh": cert["verdict_label_zh"],
        "issued_at": cert["issued_at"],
        "snapshot_digest": signing.snapshot_digest(cert["snapshot"]),
        "snapshot_digest_alg": signing.DIGEST_ALG_SHA256,
        "key_id": key_row["key_id"],
        "alg": signing.SIGNATURE_ALG,
        "issued_by": DEFAULT_ISSUER,
    }


def issue_verification_package(
    conn: sqlite3.Connection, certificate_id: int
) -> dict[str, Any]:
    """向馆外接收方出具一张已签发证书的核验包（只读，不落记录）。

    原证书与不可变快照不修改、不复制：包内只带快照摘要（canonical JSON 的
    SHA-256 hex）。库内尚无签名密钥时在本事务内生成首把（本地自动初始化）。
    证书不存在 -> 404（沿用既有证书接口约定）。
    """
    # BEGIN IMMEDIATE：确保“取 active 密钥/必要时生成首把”与并发轮换串行
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT * FROM certificates WHERE id=?", (certificate_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"证书 {certificate_id} 不存在，无法出具核验包",
            )
        key_row = _get_active_key_row(conn)
        if key_row is None:
            key_row = _insert_generated_active_key(
                conn, "首次出具核验包：本地自动生成签名密钥")
        cert = certificate_to_dict(row)
        fields = _unsigned_package_fields(cert, key_row)
        private_key = signing.parse_private_key_pem(key_row["private_key_pem"])
        signature_bytes = signing.rs256_sign(
            private_key, signing.canonical_json_bytes(fields))
        fields["signature"] = base64.b64encode(signature_bytes).decode("ascii")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return {"effect": "issued", "package": fields}


# ------------------------------------------------------------ 接收方核验

def _certificate_current_status(
    conn: sqlite3.Connection, row: sqlite3.Row
) -> dict[str, Any]:
    """该证书相对于所属窗口当前已提交状态的可用性（最新未撤销才算当前可用）。"""
    revoked_reason = row["revoked_reason"]
    revoked = revoked_reason is not None
    latest = conn.execute(
        "SELECT id, version FROM certificates WHERE window_id=? ORDER BY version DESC LIMIT 1",
        (row["window_id"],),
    ).fetchone()
    latest_version = latest["version"] if latest else None
    is_latest = latest is not None and latest["id"] == row["id"]
    currently_usable = not revoked and is_latest

    if revoked:
        status_value = "revoked"
        label = "已撤销"
        reason = (
            f"证书已被撤销（{revoked_reason}）：其历史内容仍可凭本包核验，"
            "但不是当前可用证书。"
        )
    elif not is_latest:
        reason = (
            f"该证书（版本 {row['version']}）已被同窗口更新签发版本"
            f"（最新为版本 {latest_version}）替代：历史包仍可信，"
            "但它不是当前可用证书。"
        )
        status_value = "superseded"
        label = "已被新版本替代"
    else:
        status_value = "current"
        label = "当前可用"
        reason = "该证书仍为所属窗口最新签发且未撤销版本，当前可用。"

    return {
        "certificate_id": row["id"],
        "window_id": row["window_id"],
        "version": row["version"],
        "verdict": row["verdict"],
        "verdict_label_zh": VERDICT_LABELS_ZH.get(row["verdict"], row["verdict"]),
        "revoked": revoked,
        "revocation": (
            {"reason": revoked_reason, "revoked_at": row["revoked_at"]}
            if revoked else None
        ),
        "is_latest_version": is_latest,
        "currently_usable": currently_usable,
        "status": status_value,
        "status_label_zh": label,
        "reason_zh": reason,
        "latest_version": latest_version,
    }


def _untrusted(status_code: int, detail: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail=detail)


def verify_verification_package(
    conn: sqlite3.Connection, package: dict[str, Any]
) -> dict[str, Any]:
    """接收方提交核验包核验（只读；调用方持有读事务，取同一已提交状态）。

    任一项不通过即明确拒绝（404/422，仅 detail），不出具核验结论；
    核验不改变任何业务状态。
    """
    signature_b64 = package["signature"]
    try:
        signature_bytes = base64.b64decode(signature_b64, validate=True)
    except Exception:  # 模型已拦截，防御性处理
        signature_bytes = b""
    unsigned = {k: v for k, v in package.items() if k != "signature"}

    # 1) 密钥标识必须是库中保留的签名密钥（当前或历史）——未知密钥明确拒绝
    key_row = conn.execute(
        "SELECT * FROM signing_keys WHERE key_id=?", (package["key_id"],)
    ).fetchone()
    if key_row is None:
        raise _untrusted(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"核验拒绝：未知签名密钥 {package['key_id']}（馆方未保留对应公钥，"
                "无法核验签名）。请使用馆方发布的当前或历史公钥对应的核验包。"
            ),
        )
    modulus, exponent = signing.parse_public_key_pem(key_row["public_key_pem"])

    # 2) 验签：覆盖除 signature 外全部字段（按 canonical JSON 重建报文）
    sig_ok = signing.rs256_verify(
        modulus, exponent,
        signing.canonical_json_bytes(unsigned), signature_bytes,
    )
    if not sig_ok:
        raise _untrusted(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "核验拒绝：签名不可信——验签未通过（包内字段可能被篡改，或签名"
                "与密钥/内容不匹配）。"
            ),
        )

    # 3) 对应证书必须存在（沿用既有证书接口：不存在 -> 404）
    row = conn.execute(
        "SELECT * FROM certificates WHERE id=?", (package["certificate_id"],)
    ).fetchone()
    if row is None:
        raise _untrusted(
            status.HTTP_404_NOT_FOUND,
            detail=(
                f"核验拒绝：无对应证书——标识 {package['certificate_id']} "
                "在馆方证书库中不存在（签名虽有效，但引用对象无法核实）。"
            ),
        )

    # 4) 包内不可变快照摘要必须与库中该证现有快照一致（快照不符 -> 拒绝）
    current_snapshot = json.loads(row["snapshot_json"])
    expected_digest = signing.snapshot_digest(current_snapshot)
    if expected_digest != package["snapshot_digest"]:
        raise _untrusted(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "核验拒绝：不可变快照摘要不符——包内摘要与馆方保存的该证书"
                f"现有快照摘要不一致（包内 {package['snapshot_digest']}；"
                f"现存 {expected_digest}）。"
            ),
        )

    # 5) 包内证书标识字段必须与库中同一证书一致（防张冠李戴/拼接篡改）
    mismatches: list[str] = []
    for field_name, current in (
        ("window_id", row["window_id"]),
        ("version", row["version"]),
        ("verdict", row["verdict"]),
        ("issued_at", row["issued_at"]),
    ):
        if package[field_name] != current:
            mismatches.append(f"{field_name}: 包内={package[field_name]!r} 现存={current!r}")
    current_label = VERDICT_LABELS_ZH.get(row["verdict"], row["verdict"])
    if package["verdict_label_zh"] != current_label:
        mismatches.append(
            f"verdict_label_zh: 包内={package['verdict_label_zh']!r} 现存={current_label!r}")
    if mismatches:
        raise _untrusted(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="核验拒绝：核验包内证书字段与馆方现存证书不一致（"
                   + "；".join(mismatches) + "）。",
        )

    # ---- 全部通过：给出可信结论 + 当前可用性（只读核对同一已提交状态） ----
    cert_status = _certificate_current_status(conn, row)
    if cert_status["currently_usable"]:
        conclusion = (
            f"核验通过：签名（{package['alg']}，密钥 {package['key_id'][:16]}…）与"
            "不可变快照摘要均可信；证书 "
            f"{row['id']}（窗口 {row['window_id']}，版本 {row['version']}，"
            f"结论{cert_status['verdict_label_zh']}）仍为所属窗口最新签发且未撤销版本，"
            "当前可用。"
        )
    else:
        conclusion = (
            f"核验通过：签名与不可变快照摘要均可信，本核验包为可信历史记录；"
            f"但证书 {row['id']} 目前不可用——{cert_status['reason_zh']}"
            "可信历史包不等于当前可用。"
        )
    return {
        "trusted": True,
        "currently_usable": cert_status["currently_usable"],
        "conclusion_zh": conclusion,
        "signature": {
            "trusted": True,
            "key_id": package["key_id"],
            "alg": package["alg"],
            "reason_zh": None,
        },
        "snapshot": {
            "trusted": True,
            "expected_digest": expected_digest,
            "alg": package["snapshot_digest_alg"],
            "reason_zh": None,
        },
        "certificate": cert_status,
    }
