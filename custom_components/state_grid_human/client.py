"""Low-level State Grid HTTP client with sanitized diagnostic logging."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import time
import urllib.parse
from typing import Any

from aiohttp import ClientSession

from .const import BASE_API, CLICK_CARD_API, GET_REQUEST_KEY_API, GET_VERIFY_CODE_API
from .crypto import json_compact, sm2_encrypt_key, sm3_text, sm4_encrypt_text, unwrap_data

_LOGGER = logging.getLogger(__name__)

APP_KEY = "7e5b5e84ddad4994b0ebc68dedca4962"
APP_SECRET = "2bc37a881e1541aaa6e6e174658d150b"
STATE_GRID_APP_SECRET = os.environ.get("STATE_GRID_APP_SECRET", APP_SECRET)
STATE_GRID_PUBLIC_KEY = (
    "042D12DFBC179202AC4B7B7BADCDA6FF7B604339263F6AB732CE7107B7EA3830A2CA714DC303920D3CFF7647D898F1A8CC6C24E9EC3CC194E22D984AF7E16B42DC"
)

GET_REQUEST_AUTHORIZE_API = "/oauth2/oauth/authorize"
GET_WEB_TOKEN_API = "/oauth2/outer/getWebToken"

_SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "secret", "client_secret", "authorization",
    "cookie", "set-cookie", "token", "access_token", "refresh_token", "webToken",
    "loginKey", "skey", "data", "canvasSrc", "wordSrc", "iconSrcs",
}


def _new_key_code() -> str:
    return "".join(secrets.choice("0123456789") for _ in range(32))


def _safe_value(value: Any, *, key: str = "") -> Any:
    """Keep useful diagnostics while never logging credentials/tokens."""
    if key.lower() in {item.lower() for item in _SENSITIVE_KEYS}:
        if isinstance(value, str):
            return f"<redacted len={len(value)}>"
        return "<redacted>"
    if isinstance(value, dict):
        return {str(k): _safe_value(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_safe_value(v) for v in value[:20]] + ([f"<... {len(value) - 20} more>"] if len(value) > 20 else [])
    if isinstance(value, str) and len(value) > 500:
        return f"<string len={len(value)} prefix={value[:80]!r}>"
    return value


def _try_json(raw: str) -> Any:
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return {"raw": raw}


def _mask_account(account: str) -> str:
    if not account:
        return "<empty>"
    if len(account) <= 4:
        return "*" * len(account)
    return account[:2] + "*" * (len(account) - 4) + account[-2:]


def _request_fingerprint(payload: dict[str, Any]) -> str:
    """Fingerprint the encrypted request for correlation without exposing it."""
    raw = json_compact(payload).encode()
    return hashlib.sha256(raw).hexdigest()[:12]


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
        headers = self._headers()
        payload = self._wrap({"client_id": APP_KEY, "client_secret": self.app_secret})
        payload["client_id"] = APP_KEY
        _LOGGER.debug(
            "State Grid negotiate_key: POST %s timestamp=%s payload_keys=%s data_len=%s skey_len=%s fingerprint=%s",
            GET_REQUEST_KEY_API, self.timestamp, list(payload), len(payload.get("data", "")),
            len(payload.get("skey", "")), _request_fingerprint(payload),
        )
        async with self.session.post(BASE_API + GET_REQUEST_KEY_API, json=payload, headers=headers) as response:
            raw = await response.text()
            _LOGGER.debug(
                "State Grid negotiate_key: HTTP %s content_type=%s response_len=%s body=%s",
                response.status, response.headers.get("Content-Type"), len(raw), _safe_value(_try_json(raw)),
            )
            response.raise_for_status()
            result = _try_json(raw)
        if isinstance(result.get("data"), dict):
            data = result["data"]
            self.key_code = str(data.get("keyCode") or self.key_code)
            self.public_key = str(data.get("publicKey") or self.public_key)
            _LOGGER.debug("State Grid negotiate_key: keyCode_len=%s public_key_len=%s", len(self.key_code), len(self.public_key))
        elif isinstance(result.get("data"), str):
            try:
                result["decrypted_data"] = unwrap_data(result["data"], self.key_code)
                _LOGGER.debug("State Grid negotiate_key: decrypted_data=%s", _safe_value(_try_json(result["decrypted_data"])))
            except Exception as err:
                _LOGGER.debug("State Grid negotiate_key: response decrypt failed: %s", err)
        return result

    async def get_password_captcha(self, account: str, password: str) -> dict[str, Any]:
        _LOGGER.debug(
            "State Grid password captcha: POST %s account=%s password_len=%s key_code_len=%s",
            GET_VERIFY_CODE_API, _mask_account(account), len(password), len(self.key_code),
        )
        result = await self.post_encrypted(
            GET_VERIFY_CODE_API,
            {"account": account, "password": password, "canvasHeight": 200, "canvasWidth": 310},
            session_id=True,
        )
        _LOGGER.debug("State Grid password captcha: response=%s", _safe_value(result))
        return result

    async def click_card(self, account: str, password: str, login_key: str, code: str) -> dict[str, Any]:
        data = {
            "loginKey": login_key,
            "code": code,
            "params": {
                "uscInfo": {"devciceIp": "", "tenant": "state_grid", "member": "0902", "devciceId": ""},
                "quInfo": {
                    "optSys": "android", "pushId": "000000", "addressProvince": "110100",
                    "password": password, "account": account, "addressRegion": "110101", "addressCity": "330100",
                },
            },
            "Channels": "web",
        }
        _LOGGER.debug("State Grid click captcha: endpoint=%s account=%s code=%s", CLICK_CARD_API, _mask_account(account), code)
        result = await self.post_encrypted(CLICK_CARD_API, data, session_id=True)
        self._capture_login_result(result)
        return result

    def _capture_login_result(self, value: Any) -> None:
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
        _LOGGER.debug("State Grid login result: token_present=%s access_token_present=%s user_info_keys=%s", bool(self.token), bool(self.access_token), list(self.user_info.keys()))

    async def get_authorize_code(self) -> str:
        timestamp = int(time.time() * 1000)
        form = urllib.parse.urlencode({"client_id": APP_KEY, "response_type": "code", "redirect_url": "/test", "timestamp": timestamp, "rsi": self.token or ""})
        headers = self._headers()
        headers.update({"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "keyCode": self.key_code})
        _LOGGER.debug("State Grid OAuth authorize: POST %s timestamp=%s token_present=%s", GET_REQUEST_AUTHORIZE_API, timestamp, bool(self.token))
        async with self.session.post(BASE_API + GET_REQUEST_AUTHORIZE_API, data=form, headers=headers) as response:
            raw = await response.text()
            _LOGGER.debug("State Grid OAuth authorize: HTTP %s body=%s", response.status, _safe_value(_try_json(raw)))
            response.raise_for_status()
            result = _try_json(raw)
        data = result.get("data")
        if isinstance(data, str):
            data = unwrap_data(data, self.token or "")
        if isinstance(data, str):
            try:
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
        headers = self._headers()
        payload_data = {"grant_type": "authorization_code", "sign": sm3_text(APP_KEY + str(self.timestamp)), "client_secret": self.app_secret, "state": "464606a4-184c-4beb-b442-2ab7761d0796", "key_code": self.key_code, "client_id": APP_KEY, "timestamp": self.timestamp, "code": authorize_code}
        payload = self._wrap(payload_data)
        payload["timestamp"] = str(self.timestamp)
        headers["keyCode"] = self.key_code
        _LOGGER.debug("State Grid OAuth token: POST %s code_present=%s", GET_WEB_TOKEN_API, bool(authorize_code))
        async with self.session.post(BASE_API + GET_WEB_TOKEN_API, json=payload, headers=headers) as response:
            raw = await response.text()
            _LOGGER.debug("State Grid OAuth token: HTTP %s body=%s", response.status, _safe_value(_try_json(raw)))
            response.raise_for_status()
            result = _try_json(raw)
        data = result.get("data")
        if isinstance(data, str):
            data = unwrap_data(data, self.key_code)
            try:
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
        _LOGGER.debug("State Grid password login: starting account=%s", _mask_account(account))
        result = await self.click_card(account, password, login_key, code)
        if not self.token:
            _LOGGER.error("State Grid password login: c44/f07 returned no login token; response=%s", _safe_value(result))
            raise RuntimeError("State Grid password login did not return a login token")
        authorize_code = await self.get_authorize_code()
        token_data = await self.get_web_token(authorize_code)
        _LOGGER.debug("State Grid password login: OAuth completed access_token_present=%s", bool(self.access_token))
        return {"login": result, "oauth": token_data}

    async def post_encrypted(self, endpoint: str, data: dict[str, Any], *, session_id: bool = False) -> dict[str, Any]:
        headers = self._headers()
        payload = self._wrap({
            "_access_token": self.access_token[len(self.access_token) // 2 :] if self.access_token else "",
            "_t": self.token[len(self.token) // 2 :] if self.token else "",
            "_data": data,
            "timestamp": self.timestamp,
        })
        if session_id:
            headers["sessionId"] = "web" + str(self.timestamp)
        headers["keyCode"] = self.key_code
        if self.access_token:
            headers["Authorization"] = "Bearer " + self.access_token[: len(self.access_token) // 2]
        if self.token:
            headers["t"] = self.token[: len(self.token) // 2]
        _LOGGER.debug(
            "State Grid API: POST %s session_id=%s account=%s timestamp=%s payload_keys=%s data_len=%s skey_len=%s key_code_len=%s fingerprint=%s",
            endpoint, session_id, _mask_account(str(data.get("account", ""))), self.timestamp,
            list(payload), len(payload.get("data", "")), len(payload.get("skey", "")), len(self.key_code),
            _request_fingerprint(payload),
        )
        _LOGGER.debug(
            "State Grid API headers: version=%s source=%s wsgwType=%s appKey=%s sessionId_present=%s authorization_present=%s t_present=%s",
            headers.get("version"), headers.get("source"), headers.get("wsgwType"), headers.get("appKey"),
            "sessionId" in headers, "Authorization" in headers, "t" in headers,
        )
        async with self.session.post(BASE_API + endpoint, json=payload, headers=headers) as response:
            raw = await response.text()
            parsed = _try_json(raw)
            _LOGGER.debug(
                "State Grid API: %s HTTP %s content_type=%s response_len=%s body=%s",
                endpoint, response.status, response.headers.get("Content-Type"), len(raw), _safe_value(parsed),
            )
            response.raise_for_status()
            result = parsed
        if isinstance(result.get("data"), str):
            try:
                result["decrypted_data"] = unwrap_data(result["data"], self.key_code)
                _LOGGER.debug("State Grid API: %s decrypted_data=%s", endpoint, _safe_value(_try_json(result["decrypted_data"])))
            except Exception as err:
                _LOGGER.debug("State Grid API: %s response decrypt failed: %s", endpoint, err)
        return result


def _walk(value: Any):
    yield from StateGridClient._walk(value)
