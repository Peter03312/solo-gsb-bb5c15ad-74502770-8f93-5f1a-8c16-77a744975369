"""核验包签名密码学原语（仅依赖 Python 标准库）。

- 算法：RSASSA-PKCS1-v1_5 + SHA-256（JWA 名 ``RS256``），RSA-2048（默认）。
  选 PKCS#1 v1.5 而非 PSS：签名/验签确定性口径简单、与 OpenSSL/标准工具互通，
  馆内固定文案签名场景足够（无外部依赖，故自行实现 DER/PEM 编解码与原语运算）。
- 私钥以 PKCS#1（``RSA PRIVATE KEY``）PEM 保存于本地库；公钥以 SubjectPublicKeyInfo
  （``PUBLIC KEY``）PEM 对外发布，接收方可用 OpenSSL 等标准工具直接核验：
  ``openssl dgst -sha256 -verify pubkey.pem -signature sig.bin payload.bin``。
- 密钥标识 ``key_id`` 为 SPKI DER 的 SHA-256（hex），旧公钥长期保留：
  轮换签名密钥不影响历史核验包验签；全部落库，重启后结果一致。
- 规范 JSON：``sort_keys`` + 无多余空白 + ``ensure_ascii=False``，
  签名与验签都从同结构字典重建报文，字段顺序/空白差异不影响验签。
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import secrets
from typing import Any

SIGNATURE_ALG = "RS256"          # RFC 7518：RSASSA-PKCS1-v1_5 使用 SHA-256
DIGEST_ALG_SHA256 = "sha256"
RSA_PUBLIC_EXPONENT = 65537

# rsaEncryption: 1.2.840.113549.1.1.1
_RSA_OID_DER = bytes((0x06, 0x09)) + bytes(
    (0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01)
)

# PKCS#1 v1.5 SHA-256 摘要信息 DER：SEQUENCE { SEQUENCE { OID sha256, NULL }, OCTET STRING }
_SHA256_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)


# ------------------------------------------------------------ 规范序列化与摘要

def canonical_json_bytes(data: Any) -> bytes:
    """按固定规范把对象序列化为 UTF-8 JSON 字节（签名/验签共用同一口径）。"""
    return json.dumps(
        data, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def snapshot_digest(snapshot: Any) -> str:
    """不可变快照摘要：canonical JSON(快照) 的 SHA-256 hex。

    快照在证书签发时固化为 JSON 文本存库；核验包只携带该摘要而非快照本体，
    接收方核验时由馆方比对库中同一张证书的现有快照（快照不修改、不复制）。
    """
    return sha256_hex(canonical_json_bytes(snapshot))


# ------------------------------------------------------------ 极简 DER 编解码

def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes((n,))
    body = n.to_bytes(math.ceil(n.bit_length() / 8), "big")
    return bytes((0x80 | len(body),)) + body


def _der_tlv(tag: int, content: bytes) -> bytes:
    return bytes((tag,)) + _der_len(len(content)) + content


def _der_integer(value: int) -> bytes:
    if value == 0:
        body = b"\x00"
    else:
        body = value.to_bytes(math.ceil(value.bit_length() / 8), "big")
        if body[0] & 0x80:          # 最高位为 1 时补前导 0，保持正整数
            body = b"\x00" + body
    return _der_tlv(0x02, body)


def _der_sequence(*items: bytes) -> bytes:
    return _der_tlv(0x30, b"".join(items))


class _DERReader:
    """最小 DER 读取器：只解析本模块自身写出的 INTEGER / SEQUENCE / BIT STRING。"""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def read_tlv(self) -> tuple[int, bytes]:
        tag = self.data[self.pos]
        self.pos += 1
        first = self.data[self.pos]
        self.pos += 1
        if first < 0x80:
            length = first
        else:
            n = first & 0x7F
            length = int.from_bytes(self.data[self.pos:self.pos + n], "big")
            self.pos += n
        content = self.data[self.pos:self.pos + length]
        self.pos += length
        return tag, content

    def at_end(self) -> bool:
        return self.pos == len(self.data)


def _decode_integer(content: bytes) -> int:
    return int.from_bytes(content, "big", signed=False)


def _decode_sequence(content: bytes) -> list[tuple[int, bytes]]:
    reader = _DERReader(content)
    items: list[tuple[int, bytes]] = []
    while not reader.at_end():
        items.append(reader.read_tlv())
    return items


# ------------------------------------------------------------ PEM

def _pem_wrap(der: bytes, label: str) -> str:
    b64 = base64.encodebytes(der).decode("ascii")  # 每 76 字符换行
    body = "".join(line for line in b64.splitlines(keepends=True))
    return f"-----BEGIN {label}-----\n{body}-----END {label}-----\n"


def _pem_unwrap(pem: str, expected_label: str) -> bytes:
    begin = f"-----BEGIN {expected_label}-----"
    end = f"-----END {expected_label}-----"
    lines = pem.strip().splitlines()
    if not lines or lines[0].strip() != begin:
        raise ValueError(f"PEM 解析失败：期望 {begin} 起头")
    body: list[str] = []
    for line in lines[1:]:
        line = line.strip()
        if line == end:
            break
        if line:
            body.append(line)
    else:
        raise ValueError(f"PEM 解析失败：缺少 {end} 结束标记")
    try:
        return base64.b64decode("".join(body), validate=True)
    except Exception as exc:  # noqa: BLE001 - 统一转 ValueError
        raise ValueError("PEM 解析失败：Base64 内容非法") from exc


# ------------------------------------------------------------ 公钥编码

def encode_spki_der(modulus: int, exponent: int = RSA_PUBLIC_EXPONENT) -> bytes:
    """SubjectPublicKeyInfo DER（RSA 公钥）。"""
    rsa_pub = _der_sequence(_der_integer(modulus), _der_integer(exponent))
    # BIT STRING 内容首字节为“未使用位数”（0），随后为 RSAPublicKey
    bit_string = _der_tlv(0x03, b"\x00" + rsa_pub)
    alg_id = _der_tlv(0x30, _RSA_OID_DER + _der_tlv(0x05, b""))
    return _der_tlv(0x30, alg_id + bit_string)


def decode_spki_der(der: bytes) -> tuple[int, int]:
    """SPKI DER -> (modulus, exponent)。"""
    tag, content = _DERReader(der).read_tlv()
    if tag != 0x30:
        raise ValueError("公钥解析失败：顶层不是 SEQUENCE")
    items = _decode_sequence(content)
    if len(items) != 2 or items[1][0] != 0x03:
        raise ValueError("公钥解析失败：SPKI 结构不符合预期")
    bit_content = items[1][1]
    if not bit_content or bit_content[0] != 0:
        raise ValueError("公钥解析失败：BIT STRING 未使用位数非 0")
    inner_tag, inner_content = _DERReader(bit_content[1:]).read_tlv()
    if inner_tag != 0x30:
        raise ValueError("公钥解析失败：BIT STRING 内不是 RSAPublicKey SEQUENCE")
    pub_items = _decode_sequence(inner_content)
    if len(pub_items) != 2 or pub_items[0][0] != 0x02 or pub_items[1][0] != 0x02:
        raise ValueError("公钥解析失败：RSAPublicKey 结构不符合预期")
    return _decode_integer(pub_items[0][1]), _decode_integer(pub_items[1][1])


def public_key_pem(modulus: int, exponent: int = RSA_PUBLIC_EXPONENT) -> str:
    return _pem_wrap(encode_spki_der(modulus, exponent), "PUBLIC KEY")


def parse_public_key_pem(pem: str) -> tuple[int, int]:
    return decode_spki_der(_pem_unwrap(pem, "PUBLIC KEY"))


def public_key_fingerprint(modulus: int, exponent: int = RSA_PUBLIC_EXPONENT) -> str:
    """SPKI DER 的 SHA-256 hex 作为密钥标识。"""
    return hashlib.sha256(encode_spki_der(modulus, exponent)).hexdigest()


# ------------------------------------------------------------ 私钥编码（PKCS#1）

def encode_pkcs1_der(key: dict[str, int]) -> bytes:
    """RSAPrivateKey（PKCS#1）DER：version=0 + n,e,d,p,q,dp,dq,qinvp。"""
    return _der_sequence(
        _der_integer(0),
        _der_integer(key["n"]),
        _der_integer(key["e"]),
        _der_integer(key["d"]),
        _der_integer(key["p"]),
        _der_integer(key["q"]),
        _der_integer(key["dp"]),
        _der_integer(key["dq"]),
        _der_integer(key["qi"]),
    )


def decode_pkcs1_der(der: bytes) -> dict[str, int]:
    tag, content = _DERReader(der).read_tlv()
    if tag != 0x30:
        raise ValueError("私钥解析失败：顶层不是 SEQUENCE")
    items = _decode_sequence(content)
    if len(items) < 9:
        raise ValueError("私钥解析失败：RSAPrivateKey 字段不足")
    names = ("version", "n", "e", "d", "p", "q", "dp", "dq", "qi")
    return {name: _decode_integer(items[i][1]) for i, name in enumerate(names)}


def private_key_pem(key: dict[str, int]) -> str:
    return _pem_wrap(encode_pkcs1_der(key), "RSA PRIVATE KEY")


def parse_private_key_pem(pem: str) -> dict[str, int]:
    key = decode_pkcs1_der(_pem_unwrap(pem, "RSA PRIVATE KEY"))
    if key["e"] != RSA_PUBLIC_EXPONENT:
        raise ValueError("私钥解析失败：仅支持公钥指数 65537")
    return key


# ------------------------------------------------------------ RSA 密钥生成

_SMALL_PRIMES = (
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
)


def _miller_rabin(n: int, rounds: int = 16) -> bool:
    if n < 2:
        return False
    for small in _SMALL_PRIMES:
        if n % small == 0:
            return n == small
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _random_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if all(candidate % p for p in _SMALL_PRIMES) and _miller_rabin(candidate):
            return candidate


def generate_rsa_key(bits: int = 2048) -> dict[str, int]:
    """生成 RSA 密钥对（默认 2048 位；p、q 各 bits/2 位）。"""
    if bits < 512 or bits % 2 != 0:
        raise ValueError("RSA 密钥位数必须是不小于 512 的偶数")
    half = bits // 2
    while True:
        p = _random_prime(half)
        q = _random_prime(half)
        while q == p:
            q = _random_prime(half)
        n = p * q
        if n.bit_length() != bits:
            continue  # 两高位素数相乘须恰好达到目标位数，否则重来
        phi = (p - 1) * (q - 1)
        if math.gcd(RSA_PUBLIC_EXPONENT, phi) != 1:
            continue
        e = RSA_PUBLIC_EXPONENT
        d = pow(e, -1, phi)
        dp = d % (p - 1)
        dq = d % (q - 1)
        qi = pow(q, -1, p)
        return {"version": 0, "n": n, "e": e, "d": d, "p": p, "q": q,
                "dp": dp, "dq": dq, "qi": qi}


# ------------------------------------------------------------ RSASSA-PKCS1-v1_5

def _emsa_pkcs1_v15(message: bytes, em_len: int) -> bytes:
    """RFC 8017 §9.2 编码：0x00 0x01 0xFF...0xFF 0x00 || T（T=DigestInfo）。"""
    t = _SHA256_PREFIX + hashlib.sha256(message).digest()
    if em_len < len(t) + 11:
        raise ValueError("RSA 模数过短，无法容纳签名编码")
    padding = b"\xff" * (em_len - len(t) - 3)
    return b"\x00\x01" + padding + b"\x00" + t


def _modulus_byte_len(modulus: int) -> int:
    return math.ceil(modulus.bit_length() / 8)


def rs256_sign(key: dict[str, int], message: bytes) -> bytes:
    """RSASSA-PKCS1-v1_5 + SHA-256 签名（确定性编码，输出 k 字节大端整数）。"""
    em = _emsa_pkcs1_v15(message, _modulus_byte_len(key["n"]))
    signature_int = pow(int.from_bytes(em, "big"), key["d"], key["n"])
    return signature_int.to_bytes(_modulus_byte_len(key["n"]), "big")


def rs256_verify(modulus: int, exponent: int, message: bytes, signature: bytes) -> bool:
    """验签：先做长度/范围检查，再比对 PKCS#1 v1.5 编码（常量时间比较）。"""
    k = _modulus_byte_len(modulus)
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= modulus:
        return False
    em = pow(s, exponent, modulus).to_bytes(k, "big")
    expected = _emsa_pkcs1_v15(message, k)
    return secrets.compare_digest(em, expected)
