"""Low-level State Grid HTTP client.

The login flow keeps captcha solving human: the server returns the challenge,
HA shows it to the user, and only the user's click coordinates are submitted.
"""
from __future__ import annotations

import os
import secrets
import time
import urllib.parse
from typing import Any

from aiohttp import ClientSession

from .const import BASE_API, CLICK_CARD_API, GET_REQUEST_KEY_API, GET_VERIFY_CODE_API
from .crypto import json_compact, sm2_encrypt_key, sm3_text, sm4_encrypt_text, unwrap_data

APP_KEY = "7e5b5e84ddad4994b0ebc68dedca4962"
# This is the public web-gateway application credential used by the existing
# open-source State Grid client. It is not a user's account credential.
APP_SECRET = "2bc37a881e1541aaa6e6e174658d150b"
STATE_GRID_APP_SECRET = os.environ.get("STATE_GRID_APP_SECRET", APP_SECRET)
STATE_GRID_PUBLIC_KEY = (
    "042D12DFBC179202AC4B7B7BADCDA6FF7B604339263F6AB732CE7107B7EA3830A2CA714DC303920D3CFF7647D898F1A8CC6C24E9EC3CC194E22D984AF7E16B42DC"
)

GET_REQUEST_AUTHORIZE_API = "/oauth2/oauth/authorize"
GET_WEB_TOKEN_API = "/oauth2/outer/getWebToken"


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
        self.refresh_token: str | None = None
        self.token: str | None = None
        self.web_token: str | None = None
        self.user_info: dict[str, Any] = {}

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

    @staticmethod
    def _walk(value: Any):
        if isinstance(value, dict):
            yield value
            for child in value.values():
                yield from StateGridClient._walk(child)
        elif isinstance(value, list):
            for child in value:
                yield from StateGridClient._walk(child)

    async def negotiate_key(self) -> dict[str, Any]:
        """Initialize the encrypted gateway session."""
        headers = self._headers()
        payload = self._wrap({"client_id": APP_KEY, "client_secret": self.app_secret})
        payload["client_id"] = APP_KEY
        async with self.session.post(
            BASE_API + GET_REQUEST_KEY_API, json=payload, headers=headers
        ) as response:
            response.raise_for_status()
            result = await response.json()
        if isinstance(result.get("data"), dict):
            data = result["data"]
            self.key_code = str(data.get("keyCode") or self.key_code)
            self.public_key = str(data.get("publicKey") or self.public_key)
        elif isinstance(result.get("data"), str):
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
        self._capture_login_result(result)
        return result

    def _capture_login_result(self, value: Any) -> None:
        """Capture the short-lived State Grid login token returned by c44/f07."""
        for item in self._walk(value):
            if not isinstance(item, dict):
                continue
            if str(item.get("resultCode", "")) == "0000":
                biz = item.get("bizrt")
                if isinstance(biz, dict):
                    token = biz.get("token")
                    if isinstance(token, str) and token:
                        self.token = token
                user = item.get("userInfo")
                if isinstance(user, dict):
                    self.user_info = user
            for key in ("token", "accessToken", "webToken"):
                candidate = item.get(key)
                if isinstance(candidate, str) and candidate:
                    if key == "accessToken":
                        self.access_token = candidate
                    elif key == "webToken":
                        self.web_token = candidate
                    else:
                        self.token = candidate

    async def get_authorize_code(self) -> str:
        """Exchange the login token for the OAuth authorization code."""
        timestamp = int(time.time() * 1000)
        form = urllib.parse.urlencode(
            {
                "client_id": APP_KEY,
                "response_type": "code",
                "redirect_url": "/test",
                "timestamp": timestamp,
                "rsi": self.token or "",
            }
        )
        headers = self._headers()
        headers.update(
            {
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "keyCode": self.key_code,
            }
        )
        async with self.session.post(
            BASE_API + GET_REQUEST_AUTHORIZE_API, data=form, headers=headers
        ) as response:
            response.raise_for_status()
            result = await response.json()
        data = result.get("data")
        if isinstance(data, str):
            data = unwrap_data(data, self.token or "")
        if isinstance(data, str):
            try:
                import json
                data = json.loads(data)
            except ValueError:
                pass
        redirect = data.get("redirect_url") if isinstance(data, dict) else None
        if not isinstance(redirect, str):
            raise RuntimeError("State Grid OAuth authorize response has no redirect_url")
        marker = "code="
        index = redirect.rfind(marker)
        if index < 0:
            raise RuntimeError("State Grid OAuth authorize response has no code")
        return redirect[index + len(marker) : index + len(marker) + 32]

    async def get_web_token(self, authorize_code: str) -> dict[str, Any]:
        """Exchange the authorization code for OAuth access/refresh tokens."""
        headers = self._headers()
        payload_data = {
            "grant_type": "authorization_code",
            "sign": sm3_text(APP_KEY + str(self.timestamp)),
            "client_secret": self.app_secret,
            "state": "464606a4-184c-4beb-b442-2ab7761d0796",
            "key_code": self.key_code,
            "client_id": APP_KEY,
            "timestamp": self.timestamp,
            "code": authorize_code,
        }
        payload = self._wrap(payload_data)
        payload["timestamp"] = str(self.timestamp)
        headers["keyCode"] = self.key_code
        async with self.session.post(
            BASE_API + GET_WEB_TOKEN_API, json=payload, headers=headers
        ) as response:
            response.raise_for_status()
            result = await response.json()
        data = result.get("data")
        if isinstance(data, str):
            data = unwrap_data(data, self.key_code)
            try:
                import json
                data = json.loads(data)
            except ValueError:
                pass
        if not isinstance(data, dict) or not data.get("access_token"):
            raise RuntimeError("State Grid OAuth token response has no access_token")
        self.access_token = str(data["access_token"])
        self.refresh_token = str(data.get("refresh_token") or "")
        self.web_token = self.access_token
        return data

    async def login_password(self, account: str, password: str, login_key: str, code: str) -> dict[str, Any]:
        """Complete password login and OAuth token exchange."""
        result = await self.click_card(account, password, login_key, code)
        if not self.token:
            raise RuntimeError("State Grid password login did not return a login token")
        authorize_code = await self.get_authorize_code()
        token_data = await self.get_web_token(authorize_code)
        return {"login": result, "oauth": token_data}

    async def post_encrypted(
        self, endpoint: str, data: dict[str, Any], *, session_id: bool = False
    ) -> dict[str, Any]:
        headers = self._headers()
        payload = self._wrap(
            {
                "_access_token": self.access_token[len(self.access_token) // 2 :]
                if self.access_token else "",
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
        async with self.session.post(BASE_API + endpoint, json=payload, headers=headers) as response:
            response.raise_for_status()
            result = await response.json()
        if isinstance(result.get("data"), str):
            try:
                result["decrypted_data"] = unwrap_data(result["data"], self.key_code)
            except Exception:
                pass
        return result


def _walk(value: Any):
    yield from StateGridClient._walk(value)
