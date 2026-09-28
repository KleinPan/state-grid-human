"""Low-level State Grid HTTP client.

This module intentionally stops at the protocol boundary. It does not solve a
captcha; captcha coordinates are supplied by the human captcha page.
"""
from __future__ import annotations

import secrets
import time
from typing import Any

from aiohttp import ClientSession

from .const import BASE_API, GET_REQUEST_KEY_API
from .crypto import json_compact, sm3_text, sm2_encrypt_key, sm4_encrypt_text, unwrap_data

# These are public application-level identifiers used by the reference web
# client. They are not a user's account credentials.
APP_KEY = "7e5b5e84ddad4994b0ebc68dedca4962"
APP_SECRET = "2bc37a881e1541aaa6e6e174658d150b"
STATE_GRID_PUBLIC_KEY = (
    "042D12DFBC179202AC4B7B7BADCDA6FF7B604339263F6AB732CE7107B7EA3830A2CA714DC303920D3CFF7647D898F1A8CC6C24E9EC3CC194E22D984AF7E16B42DC"
)


class StateGridClient:
    """Minimal encrypted HTTP transport."""

    def __init__(self, session: ClientSession) -> None:
        self.session = session
        self.key_code = secrets.token_hex(16)
        self.public_key = STATE_GRID_PUBLIC_KEY
        self.timestamp = 0

    def _headers(self) -> dict[str, str]:
        self.timestamp = int(time.time() * 1000)
        return {
            "Accept": "application/json;charset=UTF-8",
            "Content-Type": "application/json;charset=UTF-8",
            "version": "1.0",
            "appId": "0901",
            "timestamp": str(self.timestamp),
            "wsgwType": "web",
            "appKey": APP_KEY,
        }

    async def negotiate_key(self) -> dict[str, Any]:
        """Request the gateway key material.

        The exact response wrapper has changed between State Grid gateway
        versions, so the decrypted result is returned to the caller rather
        than being silently interpreted here.
        """
        headers = self._headers()
        body = {"client_id": APP_KEY, "client_secret": APP_SECRET}
        encrypted = sm4_encrypt_text(json_compact(body), self.key_code)
        payload = {
            "data": encrypted + sm3_text(encrypted + str(self.timestamp)),
            "skey": sm2_encrypt_key(self.key_code, self.public_key),
            "client_id": APP_KEY,
            "timestamp": str(self.timestamp),
        }
        async with self.session.post(BASE_API + GET_REQUEST_KEY_API, json=payload, headers=headers) as response:
            response.raise_for_status()
            result = await response.json()
        if isinstance(result.get("data"), str):
            try:
                result["decrypted_data"] = unwrap_data(result["data"], self.key_code)
            except Exception:
                pass
        return result
