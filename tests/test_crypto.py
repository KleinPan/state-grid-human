from custom_components.state_grid_human.crypto import (
    json_compact,
    sm3_text,
    sm4_decrypt_text,
    sm4_encrypt_text,
)


def test_json_compact_is_stable() -> None:
    assert json_compact({"b": 2, "a": "中文"}) == '{"b":2,"a":"中文"}'


def test_sm3_is_hex() -> None:
    digest = sm3_text("hello")
    assert len(digest) == 64
    int(digest, 16)


def test_sm4_round_trip_with_web_keycode() -> None:
    key_code = "01234567890123456789012345678901"
    plain = '{"account":"demo","password":"secret"}'
    encrypted = sm4_encrypt_text(plain, key_code)
    assert encrypted != plain
    assert sm4_decrypt_text(encrypted, key_code) == plain
