"""State Grid captcha protocol helpers."""
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
    return {
        "account": account,
        "password": password,
        "canvasHeight": 200,
        "canvasWidth": 310,
    }


def clicks_to_code(clicks: list[dict[str, int]]) -> str:
    """Convert browser clicks to the f07 x,y|x,y representation."""
    return "|".join(f"{item['x']},{item['y']}" for item in clicks)


def build_click_payload(
    *, account: str, password: str, login_key: str, code: str
) -> dict[str, Any]:
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
                "addressRegion": "110101",
                "account": account,
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
    "clicks_to_code",
]
