"""State Grid captcha protocol helpers.

The endpoint names and the f07 payload shape mirror the public reference
implementation. Network encryption/key negotiation is kept isolated here so
it can be updated when 95598 changes its protocol.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .const import CLICK_CARD_API, GET_VERIFY_CODE_API


@dataclass(slots=True)
class CaptchaPayload:
    login_key: str
    ticket: str
    canvas: str
    icons: list[str]
    target_text: str
    width: int = 310
    height: int = 200


def build_get_captcha_payload(account: str, password: str) -> dict[str, Any]:
    """Build the f05 captcha request body."""
    return {
        "account": account,
        "password": password,
        "canvasHeight": 200,
        "canvasWidth": 310,
    }


def build_click_payload(
    *, account: str, password: str, login_key: str, code: str
) -> dict[str, Any]:
    """Build the f07 click-card request body."""
    return {
        "loginKey": login_key,
        "code": code,
        "params": {
            "uscInfo": {
                "devciceIp": "",
                "tenant": "state_grid",
                "member": "0902",
                "devciceId": "",
            },
            "quInfo": {
                "optSys": "android",
                "pushId": "000000",
                "addressProvince": "110100",
                "password": password,
                "account": account,
                "addressRegion": "110101",
                "addressCity": "330100",
            },
        },
        "Channels": "web",
    }


__all__ = [
    "CaptchaPayload",
    "CLICK_CARD_API",
    "GET_VERIFY_CODE_API",
    "build_click_payload",
    "build_get_captcha_payload",
]
