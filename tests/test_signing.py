"""签名原语单元测试（app.signing，仅标准库）。

覆盖：RSA 密钥生成、PKCS#1/SPKI PEM 往返、RS256 签名/验签、篡改拒绝、
canonical JSON 稳定性、密钥标识；若环境存在 OpenSSL，则额外验证与
openssl dgst -sha256 的双向互通（我方签的 OpenSSL 可验，反之亦然）。

运行：PYTHONPATH=. python -m pytest tests/test_signing.py -q
"""
from __future__ import annotations

import shutil
import subprocess

import pytest

from app import signing


def test_generate_rsa_key_structure():
    key = signing.generate_rsa_key(512)
    assert key["n"].bit_length() == 512
    assert key["e"] == 65537
    assert key["version"] == 0
    assert key["p"] * key["q"] == key["n"]
    assert (key["e"] * key["d"]) % ((key["p"] - 1) * (key["q"] - 1)) == 1
    assert key["dp"] == key["d"] % (key["p"] - 1)
    assert key["dq"] == key["d"] % (key["q"] - 1)
    assert (key["q"] * key["qi"]) % key["p"] == 1


def test_pem_round_trips():
    key = signing.generate_rsa_key(512)
    assert signing.parse_private_key_pem(signing.private_key_pem(key)) == key
    n, e = signing.parse_public_key_pem(signing.public_key_pem(key["n"], key["e"]))
    assert (n, e) == (key["n"], key["e"])
    assert "BEGIN RSA PRIVATE KEY" in signing.private_key_pem(key)
    assert "BEGIN PUBLIC KEY" in signing.public_key_pem(key["n"])


def test_sign_verify_and_tamper():
    key = signing.generate_rsa_key(512)
    message = signing.canonical_json_bytes({"b": 1, "a": "中文", "c": [1, 2, {"d": None}]})
    sig = signing.rs256_sign(key, message)
    assert len(sig) == 64
    assert signing.rs256_verify(key["n"], key["e"], message, sig)
    # 报文被改 / 签名被改 / 长度异常 -> 验签失败
    assert not signing.rs256_verify(key["n"], key["e"], message + b"x", sig)
    broken = bytearray(sig); broken[10] ^= 0x01
    assert not signing.rs256_verify(key["n"], key["e"], message, bytes(broken))
    assert not signing.rs256_verify(key["n"], key["e"], message, sig + b"\x00")
    assert not signing.rs256_verify(key["n"], key["e"], message, sig[:-1])
    assert not signing.rs256_verify(key["n"], key["e"], message, b"")
    # 错误公钥（另一把钥匙）验签失败
    other = signing.generate_rsa_key(512)
    assert not signing.rs256_verify(other["n"], other["e"], message, sig)


def test_canonical_json_is_stable_and_order_independent():
    a = {"z": 1, "a": [1, 2, 3], "m": {"y": True, "x": None}}
    b = {"m": {"x": None, "y": True}, "a": [1, 2, 3], "z": 1}
    assert signing.canonical_json_bytes(a) == signing.canonical_json_bytes(b)
    encoded = signing.canonical_json_bytes(a)
    # 无多余空白、键排序
    assert encoded == b'{"a":[1,2,3],"m":{"x":null,"y":true},"z":1}'
    # 非有限数禁止规范化（防止 NaN 产生非唯一 JSON）
    with pytest.raises(ValueError):
        signing.canonical_json_bytes({"x": float("nan")})


def test_snapshot_digest_stable():
    snapshot1 = {"window": {"id": 1}, "readings": [{"reading_id": "a"}]}
    snapshot2 = {"readings": [{"reading_id": "a"}], "window": {"id": 1}}
    d1 = signing.snapshot_digest(snapshot1)
    assert d1 == signing.snapshot_digest(snapshot2)
    assert len(d1) == 64 and all(ch in "0123456789abcdef" for ch in d1)
    assert signing.snapshot_digest({"x": 1}) != signing.snapshot_digest({"x": 2})


def test_key_id_is_spki_fingerprint():
    key = signing.generate_rsa_key(512)
    key_id = signing.public_key_fingerprint(key["n"], key["e"])
    n, e = signing.parse_public_key_pem(signing.public_key_pem(key["n"]))
    assert signing.public_key_fingerprint(n, e) == key_id
    other = signing.generate_rsa_key(512)
    assert signing.public_key_fingerprint(other["n"], other["e"]) != key_id


def test_parse_rejects_wrong_pem_label():
    key = signing.generate_rsa_key(512)
    with pytest.raises(ValueError):
        signing.parse_public_key_pem(signing.private_key_pem(key))
    with pytest.raises(ValueError):
        signing.parse_private_key_pem(signing.public_key_pem(key["n"]))


@pytest.mark.skipif(shutil.which("openssl") is None, reason="环境无 openssl 命令")
def test_openssl_interop_2048(tmp_path):
    """2048 位密钥与系统 OpenSSL 双向互通（PEM/DER 编码正确性端到端验证）。"""
    key = signing.generate_rsa_key(2048)
    pub_pem = tmp_path / "pub.pem"
    priv_pem = tmp_path / "priv.pem"
    msg_path = tmp_path / "msg.bin"
    sig_path = tmp_path / "sig.bin"
    pub_pem.write_text(signing.public_key_pem(key["n"]))
    priv_pem.write_text(signing.private_key_pem(key))
    message = signing.canonical_json_bytes({"package_type": "certificate-verification-package"})
    msg_path.write_bytes(message)

    # 我方签名 -> OpenSSL 验签
    sig_path.write_bytes(signing.rs256_sign(key, message))
    out = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", str(pub_pem),
         "-signature", str(sig_path), str(msg_path)],
        capture_output=True, text=True,
    )
    assert out.returncode == 0 and "OK" in out.stdout, out.stderr

    # OpenSSL 私钥自检
    check = subprocess.run(
        ["openssl", "pkey", "-in", str(priv_pem), "-check", "-noout"],
        capture_output=True, text=True,
    )
    assert check.returncode == 0, check.stderr

    # OpenSSL 签名 -> 我方验签
    sig2 = tmp_path / "sig2.bin"
    sign = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(priv_pem),
         "-out", str(sig2), str(msg_path)],
        capture_output=True, text=True,
    )
    assert sign.returncode == 0, sign.stderr
    assert signing.rs256_verify(key["n"], key["e"], message, sig2.read_bytes())


@pytest.mark.skipif(shutil.which("openssl") is None, reason="环境无 openssl 命令")
def test_openssl_generated_key_our_verify(tmp_path):
    """OpenSSL 生成的 RSA 私钥导出 SPKI 公钥后，我方实现可解析并验签。"""
    priv_pem = tmp_path / "os_priv.pem"
    pub_pem = tmp_path / "os_pub.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA",
                    "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(priv_pem)],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(priv_pem), "-pubout",
                    "-out", str(pub_pem)], check=True, capture_output=True)
    n, e = signing.parse_public_key_pem(pub_pem.read_text())
    assert e == 65537 and n.bit_length() == 2048
