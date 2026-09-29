"""Low-level State Grid HTTP client.

Captcha solving is deliberately outside this class. The authentication flow
accepts only the result of a human-completed captcha challenge.
"""
from __future__ import annotations

import os
import secrets
import time
from typing import Any

from aiohttp import ClientSession

from .const import BASE_API, CLICK_CARD_API, GET_REQUEST_KEY_API, GET_VERIFY_CODE_API
from .crypto import json_compact, sm2_encrypt_key, sm3_text, sm4_encrypt_text, unwrap_data

APP_KEY = "7e5b5e84ddad4994b0ebc68dedca4962"
STATE_GRID_APP_SECRET = os.environ.get("STATE_GRID_APP_SECRET", "")
STATE_GRID_PUBLIC_KEY = (
    "042D12DFBC179202AC4B7B7BADCDA6FF7B604339263F6AB732CE7107B7EA3830A2CA714DC303920D3CFF7647D898F1A8CC6C24E9EC3CC194E22D984AF7E16B42DC"
)


def _new_key_code() -> str:
    return "".join(secrets.choice("0123456789") for _ in range(32))


class StateGridClient:
    """Encrypted State Grid gateway client."""

    def __init__(self, session: ClientSession, app_secret: str | None = None) -> None:
        self.session = session
        self.app_secret = app_secret or STATE_GRID_APP_SECRET
        self.key_code = _new_key_code()
        self.public_key = STATE_GRID_PUBLIC_KEY
        self.timestamp = 0
        self.access_token: str | None = None
        self.token: str | None = None
        self.web_token: str | None = None

    def _headers(self) -> dict[str, str]:
        self.timestamp = int(time.time() * 1000)
        return {
            "Accept": "application/json;charset=UTF-8",
            "Content-Type": "application/json;charset=UTF-8",
            "version": "1.0",
            "source": "0901",
            "timestamp": str(self.timestamp),
            "wsgwType": "web",
            "appKey": APP_KEY,
        }

    def _wrap(self, data: dict[str, Any]) -> dict[str, str]:
        encrypted = sm4_encrypt_text(json_compact(data), self.key_code)
        return {
            "data": encrypted + sm3_text(encrypted + str(self.timestamp)),
            "skey": sm2_encrypt_key(self.key_code, self.public_key),
            "timestamp": str(self.timestamp),
        }

    async def negotiate_key(self) -> dict[str, Any]:
        """Initialize the encrypted gateway session."""
        if not self.app_secret:
            raise RuntimeError("STATE_GRID_APP_SECRET is not configured")
        headers = self._headers()
        payload = self._wrap(
            {"client_id": APP_KEY, "client_secret": self.app_secret}
        )
        payload["client_id"] = APP_KEY
        async with self.session.post(
            BASE_API + GET_REQUEST_KEY_API, json=payload, headers=headers
        ) as response:
            response.raise_for_status()
            result = await response.json()
        if isinstance(result.get("data"), str):
            try:
                result["decrypted_data"] = unwrap_data(result["data"], self.key_code)
            except Exception:
                pass
        return result

    async def get_password_captcha(self, account: str, password: str) -> dict[str, Any]:
        return await self.post_encrypted(
            GET_VERIFY_CODE_API,
            {"account": account, "password": password, "canvasHeight": 200, "canvasWidth": 310},
            session_id=True,
        )

    async def click_card(
        self, account: str, password: str, login_key: str, code: str
    ) -> dict[str, Any]:
        data = {
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
        result = await self.post_encrypted(CLICK_CARD_API, data, session_id=True)
        self._capture_tokens(result)
        return result

    def _capture_tokens(self, value: Any) -> None:
        """Capture explicit authentication token fields from decrypted data."""
        for item in _walk(value):
            if not isinstance(item, dict):
                continue
            for key, candidate in item.items():
                if not isinstance(candidate, str) or not candidate:
                    continue
                normalized = key.replace("_", "").lower()
                if normalized in {"webtoken", "accesstoken"}:
                    self.web_token = candidate
                elif normalized == "token":
                    self.token = candidate
        if self.web_token and not self.access_token:
            self.access_token = self.web_token

    async def post_encrypted(
        self, endpoint: str, data: dict[str, Any], *, session_id: bool = False
    ) -> dict[str, Any]:
        headers = self._headers()
        payload = self._wrap(
            {
                "_access_token": self.access_token[len(self.access_token) // 2 :]
                if self.access_token
                else "",
                "_t": self.token[len(self.token) // 2 :] if self.token else "",
                "_data": data,
                "timestamp": self.timestamp,
            }
        )
        if session_id:
            headers["sessionId"] = "web" + str(self.timestamp)
        headers["keyCode"] = self.key_code
        if self.access_token:
            headers["Authorization"] = "Bearer " + self.access_token[: len(self.access_token) // 2]
        if self.token:
            headers["t"] = self.token[: len(self.token) // 2]
        async with self.session.post(
            BASE_API + endpoint, json=payload, headers=headers
        ) as response:
            response.raise_for_status()
            result = await response.json()
        if isinstance(result.get("data"), str):
            try:
                result["decrypted_data"] = unwrap_data(result["data"], self.key_code)
            except Exception:
                pass
        return result


def _walk(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)
