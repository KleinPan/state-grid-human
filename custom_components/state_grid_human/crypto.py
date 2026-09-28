"""Small SM2/SM3/SM4 compatibility layer used by the State Grid protocol.

The reference integration uses a JavaScript-compatible SM4-CBC wrapper and
SM2 encryption.  gmssl is used here instead of carrying a large custom crypto
implementation in the integration.
"""
from __future__ import annotations

import base64
import json
from typing import Any

from gmssl import func, sm2, sm3, sm4


def json_compact(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def sm3_text(value: str) -> str:
    return sm3.sm3_hash(func.bytes_to_list(value.encode("utf-8")))


def _sm4_key(key_code: str) -> bytes:
    # keyCode is a 32-character hexadecimal string in the reference client.
    if len(key_code) == 32:
        try:
            return bytes.fromhex(key_code)
        except ValueError:
            pass
    return key_code.encode("utf-8")[:16].ljust(16, b"0")


def _sm4_iv(key_code: str) -> bytes:
    raw = key_code.encode("utf-8")
    return (raw[:8] + raw[-8:]).ljust(16, b"0")[:16]


def sm4_encrypt_text(value: str, key_code: str) -> str:
    crypt = sm4.CryptSM4()
    crypt.set_key(_sm4_key(key_code), sm4.SM4_ENCRYPT)
    encrypted = crypt.crypt_cbc(_sm4_iv(key_code), value.encode("utf-8"))
    return base64.b64encode(encrypted).decode("ascii")


def sm4_decrypt_text(value: str, key_code: str) -> str:
    crypt = sm4.CryptSM4()
    crypt.set_key(_sm4_key(key_code), sm4.SM4_DECRYPT)
    decrypted = crypt.crypt_cbc(_sm4_iv(key_code), base64.b64decode(value))
    return decrypted.decode("utf-8")


def sm2_encrypt_key(key_code: str, public_key: str) -> str:
    # The reference client first converts the UTF-8 key string to its hex text
    # representation before SM2 encryption.
    plain = key_code.encode("utf-8").hex().encode("ascii")
    crypt = sm2.CryptSM2(public_key=public_key.removeprefix("04"), private_key="")
    return "04" + crypt.encrypt(plain).hex()


def wrap_payload(data: dict[str, Any], key_code: str, public_key: str, timestamp: int) -> dict[str, str]:
    encrypted = sm4_encrypt_text(json_compact(data), key_code)
    return {
        "data": encrypted + sm3_text(encrypted + str(timestamp)),
        "skey": sm2_encrypt_key(key_code, public_key),
        "timestamp": str(timestamp),
    }


def unwrap_data(value: str, key_code: str) -> Any:
    plain = sm4_decrypt_text(value, key_code)
    return json.loads(plain)
