"""HTTP API 集成测试：证书核验包（verification package）。

覆盖：
- 出具：含证书标识/版本/结论/签发时间/不可变快照摘要/密钥标识/签名；
  签名覆盖除 signature 外全部字段；出具只读，不改证书/快照、不落记录；
  证书不存在 -> 404；同一证书重复出具结果一致（除签发后确定性签名相同）；
- 核验：可信且当前可用 -> trusted + current；
  撤销后：仍可信但 currently_usable=false（status=revoked，带撤销原因）；
  新版本签发后旧版包：可信但 superseded；撤销最新版不退回旧版；
- 拒绝：字段篡改（签名失败）422、签名篡改 422、未知密钥 422、
  包内快照摘要不符 422、包内证书字段与现存不一致 422、
  额外字段 422、非 hex 摘要/密钥/非法 base64 签名 422、
  有效签名但无对应证书（跨库）404；核验为只读不改业务状态；
- 轮换：新包用新密钥、旧包凭 retired 历史公钥仍可验；密钥列表含公钥不含私钥；
  重启（同 DB 文件）后结果一致；密钥持久化后跨进程仍可验；
- 沿用既有证书/撤销/当前证书接口的响应约定。

运行：PYTHONPATH=. python -m pytest tests/test_verification_package_api.py -q
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.database import connect, read_transaction
from app import signing, verification_packages


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_file = tmp_path / "test.db"
    monkeypatch.setattr(settings, "db_path", str(db_file))
    monkeypatch.setattr(settings, "db_timeout", 5)
    # 测试用小密钥加速（签名算法与编码不变；另见 test_signing 的 2048 互操作）
    monkeypatch.setattr(settings, "signing_key_bits", 512)
    from app.main import app

    with TestClient(app) as c:
        yield c


WINDOW_BASE = "2026-10-01T00:00:00Z"


def make_window(client, minutes=10, tmin=18.0, tmax=22.0,
                max_exceed=300.0, max_gap=600.0, name=None, start=WINDOW_BASE):
    start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
    end = (start_dt + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")
    body = {
        "start_at": start,
        "end_at": end,
        "allowed_temp_min": tmin,
        "allowed_temp_max": tmax,
        "max_continuous_exceed_seconds": max_exceed,
        "max_sample_interval_seconds": max_gap,
    }
    if name:
        body["name"] = name
    r = client.post("/api/v1/windows", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def reading(rid, rev, minute, temp, base=WINDOW_BASE):
    ts = datetime.fromisoformat(base.replace("Z", "+00:00")) + timedelta(minutes=minute)
    return {
        "reading_id": rid, "revision": rev,
        "measured_at": ts.isoformat().replace("+00:00", "Z"),
        "temperature": temp,
    }


def issue(client, wid=1, note=None):
    return client.post(f"/api/v1/windows/{wid}/certificates/issue",
                       json={"note": note} if note is not None else {})


def revoke(client, cid, reason):
    return client.post(f"/api/v1/certificates/{cid}/revocation", json={"reason": reason})


def issue_package(client, cid):
    r = client.post(f"/api/v1/certificates/{cid}/verification-package")
    assert r.status_code == 201, r.text
    return r.json()["package"]


def verify(client, pkg):
    return client.post("/api/v1/verification-packages/verify", json=pkg)


def seed_pass(client, max_gap=600.0):
    """满覆盖、温度全在区间 -> pass 的窗口 1 与证书 1。"""
    make_window(client, max_gap=max_gap)
    client.post("/api/v1/windows/1/readings", json=reading("a", 1, 0, 20.0))
    client.post("/api/v1/windows/1/readings", json=reading("b", 1, 10, 20.0))
    cert = issue(client, note="首签")
    assert cert.status_code == 201
    return cert.json()


# ------------------------------------------------------------ 出具

def test_issue_package_fields_and_deterministic(client):
    cert = seed_pass(client)
    pkg = issue_package(client, cert["id"])

    for field_ in ("package_type", "package_version", "certificate_id", "window_id",
                   "version", "verdict", "verdict_label_zh", "issued_at",
                   "snapshot_digest", "snapshot_digest_alg", "key_id", "alg",
                   "issued_by", "signature"):
        assert field_ in pkg, field_
    assert pkg["package_type"] == "certificate-verification-package"
    assert pkg["package_version"] == 1
    assert pkg["certificate_id"] == cert["id"]
    assert pkg["window_id"] == cert["window_id"]
    assert pkg["version"] == cert["version"] == 1
    assert pkg["verdict"] == "pass"
    assert pkg["verdict_label_zh"] == "合格"
    assert pkg["issued_at"] == cert["issued_at"]
    assert pkg["alg"] == "RS256" and pkg["snapshot_digest_alg"] == "sha256"
    assert pkg["issued_by"] == "museum-audit-service"
    assert len(pkg["snapshot_digest"]) == 64
    assert len(pkg["key_id"]) == 64
    assert len(base64.b64decode(pkg["signature"])) == 64  # RSA-512 测试密钥 64 字节

    # 快照摘要与证书现存不可变快照的 canonical-JSON SHA-256 一致
    expected = signing.snapshot_digest(cert["snapshot"])
    assert pkg["snapshot_digest"] == expected

    # 重复出具：同一当前密钥下确定性签名，包内容完全一致；不落任何业务记录
    pkg2 = issue_package(client, cert["id"])
    assert pkg2 == pkg
    certs = client.get("/api/v1/windows/1/certificates").json()
    assert len(certs) == 1  # 出具核验包不签发新版本


def test_issue_package_does_not_modify_certificate_or_snapshot(client):
    cert = seed_pass(client)
    before = client.get(f"/api/v1/certificates/{cert['id']}").json()
    issue_package(client, cert["id"])
    issue_package(client, cert["id"])
    after = client.get(f"/api/v1/certificates/{cert['id']}").json()
    assert after == before  # 版本/结论/签发时间/快照全部原样


def test_issue_package_unknown_certificate_404(client):
    r = client.post("/api/v1/certificates/999/verification-package")
    assert r.status_code == 404
    assert "不存在" in r.json()["detail"]


def test_first_issue_creates_signing_key_persisted(client):
    seed_pass(client)
    assert client.get("/api/v1/signing-keys").json() == []  # 签发证书本身不建签名密钥
    pkg = issue_package(client, 1)
    keys = client.get("/api/v1/signing-keys").json()
    assert len(keys) == 1 and keys[0]["status"] == "active"
    assert keys[0]["key_id"] == pkg["key_id"]
    assert "PRIVATE KEY" not in json.dumps(keys)
    # 公钥 PEM 可被标准解析为同一 (n, e)，密钥标识与 SPKI 指纹一致
    n, e = signing.parse_public_key_pem(keys[0]["public_key_pem"])
    assert signing.public_key_fingerprint(n, e) == keys[0]["key_id"]


# ------------------------------------------------------------ 核验：可信 + 当前可用

def test_verify_trusted_and_current(client):
    cert = seed_pass(client)
    pkg = issue_package(client, cert["id"])
    r = verify(client, pkg)
    assert r.status_code == 200, r.text
    res = r.json()
    assert res["trusted"] is True
    assert res["currently_usable"] is True
    assert res["signature"]["trusted"] is True
    assert res["signature"]["key_id"] == pkg["key_id"]
    assert res["snapshot"]["trusted"] is True
    assert res["snapshot"]["expected_digest"] == pkg["snapshot_digest"]
    cs = res["certificate"]
    assert cs["status"] == "current"
    assert cs["status_label_zh"] == "当前可用"
    assert cs["revoked"] is False and cs["is_latest_version"] is True
    assert cs["currently_usable"] is True
    assert cs["latest_version"] == 1


# ------------------------------------------------------------ 撤销 / 替代：可信但不可用

def test_verify_revoked_package_trusted_but_not_usable(client):
    cert = seed_pass(client)
    pkg = issue_package(client, cert["id"])
    revoke(client, cert["id"], "签发依据有误：读数 a 确认为误采")

    res = verify(client, pkg).json()
    assert res["trusted"] is True                 # 签名/快照仍可信
    assert res["currently_usable"] is False       # 但不是当前可用
    cs = res["certificate"]
    assert cs["status"] == "revoked"
    assert cs["status_label_zh"] == "已撤销"
    assert cs["revoked"] is True
    assert cs["revocation"]["reason"] == "签发依据有误：读数 a 确认为误采"
    assert "误采" in cs["reason_zh"]
    assert "可信历史" in res["conclusion_zh"] or "可信历史记录" in res["conclusion_zh"]


def test_verify_superseded_package_trusted_but_not_usable(client):
    cert1 = seed_pass(client)
    pkg1 = issue_package(client, cert1["id"])
    # 新版本：修改读数后再次签发
    client.post("/api/v1/windows/1/readings", json=reading("a", 2, 0, 21.0))
    cert2 = issue(client, note="v2").json()
    assert cert2["version"] == 2

    res = verify(client, pkg1).json()
    assert res["trusted"] is True
    assert res["currently_usable"] is False
    cs = res["certificate"]
    assert cs["status"] == "superseded"
    assert cs["status_label_zh"] == "已被新版本替代"
    assert cs["is_latest_version"] is False
    assert cs["revoked"] is False
    assert cs["latest_version"] == 2
    assert "更新签发版本" in cs["reason_zh"]


def test_revoke_latest_no_fallback_old_package_still_not_current(client):
    cert1 = seed_pass(client)
    pkg1 = issue_package(client, cert1["id"])
    client.post("/api/v1/windows/1/readings", json=reading("a", 2, 0, 21.0))
    cert2 = issue(client, note="v2").json()
    # 撤销最新版 -> 不自动退回旧版；旧包为 superseded（未撤销但非最新）
    revoke(client, cert2["id"], "最新版依据有误")
    assert client.get("/api/v1/windows/1/certificates/current").status_code == 409

    res = verify(client, pkg1).json()
    assert res["trusted"] is True and res["currently_usable"] is False
    assert res["certificate"]["status"] == "superseded"


def test_revoke_old_version_does_not_affect_current(client):
    cert1 = seed_pass(client)
    client.post("/api/v1/windows/1/readings", json=reading("a", 2, 0, 21.0))
    cert2 = issue(client, note="v2").json()
    pkg2 = issue_package(client, cert2["id"])
    revoke(client, cert1["id"], "撤销旧版本")
    res = verify(client, pkg2).json()
    assert res["trusted"] is True and res["currently_usable"] is True
    assert res["certificate"]["status"] == "current"


# ------------------------------------------------------------ 明确拒绝

def test_verify_tampered_field_rejected_signature_invalid(client):
    cert = seed_pass(client)
    pkg = issue_package(client, cert["id"])
    # 受签名字段被改：通过模型校验但验签失败 -> 422 + 明确“签名不可信”
    for field_, new_value in (
        ("version", 2),
        ("verdict", "fail"),
        ("window_id", 2),
        ("issued_at", "2026-01-01T00:00:00.000Z"),
        ("issued_by", "someone-else"),
        ("certificate_id", 999),
    ):
        bad = json.loads(json.dumps(pkg))
        bad[field_] = new_value
        r = verify(client, bad)
        assert r.status_code == 422, (field_, r.text)
        assert "签名不可信" in r.json()["detail"], field_


def test_verify_fixed_value_fields_cannot_be_changed(client):
    cert = seed_pass(client)
    pkg = issue_package(client, cert["id"])
    # 固定取值字段被改：请求模型直接拒绝（422），不进入核验
    for field_, new_value in (
        ("package_version", 2),
        ("package_type", "something-else"),
        ("alg", "RS512"),
        ("snapshot_digest_alg", "sha512"),
    ):
        bad = json.loads(json.dumps(pkg))
        bad[field_] = new_value
        r = verify(client, bad)
        assert r.status_code == 422, (field_, r.text)


def test_verify_tampered_signature_rejected(client):
    cert = seed_pass(client)
    pkg = issue_package(client, cert["id"])
    sig = bytearray(base64.b64decode(pkg["signature"]))
    sig[0] ^= 0xFF
    pkg["signature"] = base64.b64encode(bytes(sig)).decode()
    r = verify(client, pkg)
    assert r.status_code == 422 and "签名不可信" in r.json()["detail"]


def test_verify_unknown_key_rejected(client):
    cert = seed_pass(client)
    pkg = issue_package(client, cert["id"])
    pkg["key_id"] = "ab" * 32
    r = verify(client, pkg)
    assert r.status_code == 422 and "未知签名密钥" in r.json()["detail"]


def test_verify_snapshot_digest_mismatch_rejected(client):
    cert = seed_pass(client)
    pkg = issue_package(client, cert["id"])
    pkg["snapshot_digest"] = "cd" * 32
    r = verify(client, pkg)
    # 摘要字段纳入签名 -> 验签先失败（明确拒绝，不出结论）
    assert r.status_code == 422 and "签名不可信" in r.json()["detail"]


def test_verify_valid_signature_but_digest_mismatch_at_server(client):
    """构造“签名有效但快照摘要被伪造”的包：用本地私钥对篡改后字段重签，
    服务端比对现存快照摘要不符 -> 422（快照不可信）。"""
    cert = seed_pass(client)
    pkg = issue_package(client, cert["id"])

    # 直接取库内 active 私钥（仅测试），对篡改摘要后的字段重新签名
    conn = connect()
    try:
        row = conn.execute(
            "SELECT * FROM signing_keys WHERE status='active'").fetchone()
        key = signing.parse_private_key_pem(row["private_key_pem"])
    finally:
        conn.close()
    forged = json.loads(json.dumps(pkg))
    forged["snapshot_digest"] = "01" * 32
    unsigned = {k: v for k, v in forged.items() if k != "signature"}
    forged["signature"] = base64.b64encode(
        signing.rs256_sign(key, signing.canonical_json_bytes(unsigned))).decode()

    r = verify(client, forged)
    assert r.status_code == 422, r.text
    assert "快照摘要不符" in r.json()["detail"]


def test_verify_valid_signature_but_certificate_fields_mismatch(client):
    """合法签名但包内 version/verdict 等与现存证书不一致（重签拼接）-> 422。"""
    cert = seed_pass(client)
    pkg = issue_package(client, cert["id"])
    conn = connect()
    try:
        row = conn.execute("SELECT * FROM signing_keys WHERE status='active'").fetchone()
        key = signing.parse_private_key_pem(row["private_key_pem"])
    finally:
        conn.close()
    forged = json.loads(json.dumps(pkg))
    forged["verdict"] = "fail"
    forged["verdict_label_zh"] = "不合格"
    unsigned = {k: v for k, v in forged.items() if k != "signature"}
    forged["signature"] = base64.b64encode(
        signing.rs256_sign(key, signing.canonical_json_bytes(unsigned))).decode()
    r = verify(client, forged)
    assert r.status_code == 422 and "不一致" in r.json()["detail"]


def test_verify_valid_signature_but_certificate_missing_404(client, tmp_path, monkeypatch):
    """有效签名包（证书曾存在）提交到无该证书的库 -> 404（无对应证书）。"""
    cert = seed_pass(client)
    pkg = issue_package(client, cert["id"])
    active = _active_key_row(client)
    # 另一个全新库（带同表结构），手动放同一签名密钥使验签通过但无证书
    other_db = tmp_path / "other.db"
    from app.database import init_db
    conn = connect(str(other_db))
    try:
        init_db(conn)
        with conn:
            conn.execute(
                "INSERT INTO signing_keys (key_id, status, public_key_pem, private_key_pem, "
                "algorithm, rotate_reason) VALUES (?,?,?,?,?,?)",
                (active["key_id"], "active", active["public_key_pem"],
                 active["private_key_pem"], "RS256", "test"),
            )
    finally:
        conn.close()

    from fastapi.testclient import TestClient as TC
    from app.main import app
    monkeypatch.setattr(settings, "db_path", str(other_db))
    with TC(app) as c2:
        r = c2.post("/api/v1/verification-packages/verify", json=pkg)
        assert r.status_code == 404, r.text
        assert "无对应证书" in r.json()["detail"]


def _active_key_row(client):
    conn = connect()
    try:
        row = conn.execute("SELECT * FROM signing_keys WHERE status='active'").fetchone()
        return dict(row)
    finally:
        conn.close()


def test_verify_extra_field_rejected(client):
    cert = seed_pass(client)
    pkg = issue_package(client, cert["id"])
    pkg["unexpected"] = 1
    r = verify(client, pkg)
    assert r.status_code == 422


def test_verify_malformed_payloads_rejected(client):
    seed_pass(client)
    base = issue_package(client, 1)
    bad_payloads = [
        {"snapshot_digest": "z" * 64},   # 非 hex
        {"key_id": "ab" * 33},           # 长度错误
        {"signature": "!!!not-base64"},  # 非法 base64
        {"signature": ""},               # 空签名
        {"package_type": "other"},
        {"alg": "none"},
        {"snapshot_digest_alg": "sha512"},
        {"package_version": 9},
    ]
    for override in bad_payloads:
        body = json.loads(json.dumps(base))
        body.update(override)
        r = verify(client, body)
        assert r.status_code == 422, (override, r.text)

    # 空 body / 缺必填字段 -> 422
    r = client.post("/api/v1/verification-packages/verify", json={})
    assert r.status_code == 422
    # 非 JSON 对象（数组/字符串）-> 422
    r = client.post("/api/v1/verification-packages/verify", json=["not", "an", "object"])
    assert r.status_code == 422


def test_verify_is_readonly(client):
    cert = seed_pass(client)
    pkg = issue_package(client, cert["id"])
    before = {
        "cert": client.get(f"/api/v1/certificates/{cert['id']}").json(),
        "certs": client.get("/api/v1/windows/1/certificates").json(),
        "window": client.get("/api/v1/windows/1").json(),
    }
    for _ in range(3):
        r = verify(client, pkg)
        assert r.status_code == 200
    # 故意提交篡改包被拒，也不改状态
    bad = json.loads(json.dumps(pkg)); bad["version"] = 9
    assert verify(client, bad).status_code == 422
    after = {
        "cert": client.get(f"/api/v1/certificates/{cert['id']}").json(),
        "certs": client.get("/api/v1/windows/1/certificates").json(),
        "window": client.get("/api/v1/windows/1").json(),
    }
    assert before == after


# ------------------------------------------------------------ 密钥轮换

def test_rotate_new_packages_use_new_key_old_packages_still_verify(client):
    cert = seed_pass(client)
    pkg_old = issue_package(client, cert["id"])
    old_key_id = pkg_old["key_id"]

    r = client.post("/api/v1/signing-keys/rotate", json={"reason": "年度密钥轮换"})
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["effect"] == "rotated"
    assert data["retired_key_ids"] == [old_key_id]
    new_key = data["key"]
    assert new_key["key_id"] != old_key_id and new_key["status"] == "active"
    assert new_key["rotate_reason"] == "年度密钥轮换"
    assert "PRIVATE KEY" not in json.dumps(new_key)

    # 旧包仍可凭 retired 历史公钥核验
    res = verify(client, pkg_old).json()
    assert res["trusted"] is True
    assert res["signature"]["key_id"] == old_key_id

    # 新包使用新密钥
    pkg_new = issue_package(client, cert["id"])
    assert pkg_new["key_id"] == new_key["key_id"]
    assert pkg_new["snapshot_digest"] == pkg_old["snapshot_digest"]  # 快照摘要与密钥无关
    assert verify(client, pkg_new).json()["trusted"] is True

    # 密钥列表：旧 retired + 新 active，均带公钥
    keys = client.get("/api/v1/signing-keys").json()
    assert [k["status"] for k in keys] == ["retired", "active"]
    assert {k["key_id"] for k in keys} == {old_key_id, new_key["key_id"]}


def test_rotate_empty_body_and_initialized_effect(client):
    # 未出具过任何包（库内无密钥）时轮换 = 初始化
    r = client.post("/api/v1/signing-keys/rotate", json={})
    assert r.status_code == 201
    assert r.json()["effect"] == "initialized"
    assert r.json()["retired_key_ids"] == []
    # 之后再轮换才是 rotated
    r2 = client.post("/api/v1/signing-keys/rotate", json={})
    assert r2.json()["effect"] == "rotated"
    assert len(r2.json()["retired_key_ids"]) == 1


def test_rotate_blank_reason_422(client):
    r = client.post("/api/v1/signing-keys/rotate", json={"reason": "   "})
    assert r.status_code == 422


def test_rotate_multiple_times_all_history_packages_verify(client):
    cert = seed_pass(client)
    packages = [issue_package(client, cert["id"])]
    for reason in ("第一次轮换", "第二次轮换"):
        client.post("/api/v1/signing-keys/rotate", json={"reason": reason})
        packages.append(issue_package(client, cert["id"]))
    key_ids = [p["key_id"] for p in packages]
    assert len(set(key_ids)) == 3
    keys = client.get("/api/v1/signing-keys").json()
    assert len(keys) == 3 and keys[-1]["status"] == "active"
    assert [k["status"] for k in keys[:-1]] == ["retired", "retired"]
    # 每一代包都仍可验
    for pkg in packages:
        assert verify(client, pkg).json()["trusted"] is True


def test_keys_persist_across_restart(tmp_path, monkeypatch):
    """重启（同 DB 文件重新建 app）后密钥与核验结果一致。"""
    db_file = tmp_path / "persist.db"
    monkeypatch.setattr(settings, "db_path", str(db_file))
    monkeypatch.setattr(settings, "signing_key_bits", 512)
    from app.main import app

    with TestClient(app):
        pass
    # 直接建窗/证书/密钥/核验包（第一生命周期内）
    with TestClient(app) as c1:
        seed_pass(c1)
        pkg = issue_package(c1, 1)
        keys_before = c1.get("/api/v1/signing-keys").json()
    # “重启”：新 TestClient、新连接
    with TestClient(app) as c2:
        keys_after = c2.get("/api/v1/signing-keys").json()
        assert keys_after == keys_before          # 密钥未重新生成
        res = c2.post("/api/v1/verification-packages/verify", json=pkg).json()
        assert res["trusted"] is True
        # 轮换后再重启：两代密钥都在，旧包仍可验
        c2.post("/api/v1/signing-keys/rotate", json={"reason": "重启后轮换"})
    with TestClient(app) as c3:
        assert verify(c3, pkg).json()["trusted"] is True
        assert len(c3.get("/api/v1/signing-keys").json()) == 2
        pkg2 = issue_package(c3, 1)
        assert verify(c3, pkg2).json()["trusted"] is True


def test_verify_same_committed_snapshot_in_read_transaction(client):
    """核验在同一读事务内完成（实现层）：并发撤销不会造成结论撕裂。"""
    cert = seed_pass(client)
    pkg = issue_package(client, cert["id"])

    # 直接在一个读事务内核验，结果与 HTTP 一致
    conn = connect()
    try:
        with read_transaction(conn):
            result = verification_packages.verify_verification_package(
                conn, {k: v for k, v in pkg.items()})
        assert result["trusted"] is True
        assert result["certificate"]["status"] == "current"
    finally:
        conn.close()
