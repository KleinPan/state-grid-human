"""Home Assistant config flow for the human captcha integration."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant import config_entries, data_entry_flow
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .captcha import CaptchaSession, STORE, normalize_clicks
from .client import StateGridClient
from .const import CAPTCHA_VIEW, DOMAIN

_LOGGER = logging.getLogger(__name__)


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Configure a State Grid account while keeping captcha interaction human."""

    VERSION = 1

    def __init__(self) -> None:
        self._account = ""
        self._password = ""
        self._client: StateGridClient | None = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> data_entry_flow.FlowResult:
        """Collect credentials and request the password-login captcha."""
        errors: dict[str, str] = {}
        if user_input:
            self._account = str(user_input["account"]).strip()
            self._password = str(user_input["password"])
            _LOGGER.debug("Config flow: credentials submitted account=%s password_len=%s", _mask_account(self._account), len(self._password))
            session = async_get_clientsession(self.hass)
            self._client = StateGridClient(session)
            try:
                key_result = await self._client.negotiate_key()
                _LOGGER.debug("Config flow: negotiate_key completed response_keys=%s", list(key_result.keys()))
                result = await self._client.get_password_captcha(self._account, self._password)
                _LOGGER.debug("Config flow: get_password_captcha completed response_keys=%s", list(result.keys()))
                captcha = _extract_captcha(result)
                if captcha is None:
                    _LOGGER.error(
                        "Config flow: captcha extraction failed. top_level_keys=%s result_code=%s message=%s nested_shapes=%s",
                        list(result.keys()),
                        _find_first(result, "resultCode"),
                        _find_first(result, "message") or _find_first(result, "msg") or _find_first(result, "errorMsg"),
                        _summarize_shapes(result),
                    )
                    errors["base"] = "captcha_response_invalid"
                else:
                    _LOGGER.debug(
                        "Config flow: captcha extracted login_key_present=%s canvas=%sx%s icons=%s target_text=%s",
                        bool(captcha.get("login_key")), captcha.get("width"), captcha.get("height"),
                        len(captcha.get("icons", [])), str(captcha.get("target_text", ""))[:80],
                    )
                    STORE.put(
                        CaptchaSession(
                            flow_id=self.flow_id,
                            login_key=captcha["login_key"],
                            account=self._account,
                            password=self._password,
                            target_text=captcha.get("target_text", "请依次点击指定图标"),
                            target_image=captcha.get("target_image", ""),
                            canvas=captcha["canvas"],
                            icons=captcha.get("icons", []),
                            width=captcha.get("width", 310),
                            height=captcha.get("height", 200),
                        )
                    )
                    return self.async_external_step(
                        step_id="captcha",
                        url_path=f"{CAPTCHA_VIEW}/{self.flow_id}",
                        description_placeholders={"url": f"{CAPTCHA_VIEW}/{self.flow_id}"},
                    )
            except Exception as err:
                _LOGGER.exception("Config flow: exception while preparing captcha: %s", err)
                errors["base"] = "cannot_connect"

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({vol.Required("account"): str, vol.Required("password"): str}),
            errors=errors,
        )

    async def async_step_captcha(
        self, user_input: dict[str, Any] | None = None
    ) -> data_entry_flow.FlowResult:
        """Receive human captcha coordinates and finish authentication."""
        if not user_input:
            _LOGGER.debug("Config flow: captcha step reopened flow_id=%s", self.flow_id)
            return self.async_external_step(
                step_id="captcha",
                url_path=f"{CAPTCHA_VIEW}/{self.flow_id}",
                description_placeholders={"url": f"{CAPTCHA_VIEW}/{self.flow_id}"},
            )

        session = STORE.get(self.flow_id)
        if session is None or self._client is None:
            _LOGGER.error("Config flow: captcha session expired or client missing flow_id=%s", self.flow_id)
            return self.async_abort(reason="captcha_expired")

        try:
            clicks = normalize_clicks(
                user_input.get("captcha_clicks"), width=session.width, height=session.height
            )
            code = "|".join(f"{item['x']},{item['y']}" for item in clicks)
            _LOGGER.debug("Config flow: captcha submitted flow_id=%s click_count=%s code=%s", self.flow_id, len(clicks), code)
            result = await self._client.login_password(
                session.account, session.password, session.login_key, code
            )
        except Exception as err:
            _LOGGER.exception("Config flow: login failed after captcha flow_id=%s: %s", self.flow_id, err)
            STORE.pop(self.flow_id)
            return self.async_abort(reason="cannot_connect")

        if not _is_login_success(result.get("login", result)) or not self._client.access_token:
            _LOGGER.error(
                "Config flow: captcha/login rejected flow_id=%s login_success=%s access_token_present=%s result_summary=%s",
                self.flow_id, _is_login_success(result.get("login", result)), bool(self._client.access_token),
                _summarize_shapes(result.get("login", result)),
            )
            STORE.pop(self.flow_id)
            return self.async_abort(reason="captcha_rejected")

        _LOGGER.info("Config flow: State Grid login succeeded account=%s", _mask_account(self._account))
        STORE.pop(self.flow_id)
        return self.async_create_entry(
            title=f"国家电网 {self._account}",
            data={
                "account": self._account,
                "access_token": self._client.access_token,
                "refresh_token": self._client.refresh_token or "",
                "login_token": self._client.token or "",
                "key_code": self._client.key_code,
                "user_info": self._client.user_info,
            },
        )


def _walk(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _find_first(value: Any, key: str) -> Any:
    for item in _walk(value):
        if key in item:
            return item[key]
    return None


def _summarize_shapes(value: Any, depth: int = 0) -> Any:
    """Log response structure without logging sensitive values or large payloads."""
    if depth > 3:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(k): _summarize_shapes(v, depth + 1) for k, v in list(value.items())[:30]}
    if isinstance(value, list):
        return {"type": "list", "len": len(value), "item": _summarize_shapes(value[0], depth + 1) if value else None}
    if isinstance(value, str):
        return {"type": "str", "len": len(value)}
    return type(value).__name__


def _mask_account(account: str) -> str:
    if not account:
        return "<empty>"
    if len(account) <= 4:
        return "*" * len(account)
    return account[:2] + "*" * (len(account) - 4) + account[-2:]


def _extract_captcha(result: dict[str, Any]) -> dict[str, Any] | None:
    """Tolerate minor response-wrapper differences in the gateway."""
    for item in _walk(result):
        canvas = item.get("canvasSrc")
        login_key = item.get("loginKey")
        if isinstance(canvas, str) and isinstance(login_key, str):
            return {
                "canvas": canvas,
                "login_key": login_key,
                "target_text": item.get("targetText") or item.get("word") or "请依次点击指定图标",
                "target_image": item.get("wordSrc") or "",
                "icons": item.get("iconSrcs") or [],
                "width": int(item.get("canvasWidth") or 310),
                "height": int(item.get("canvasHeight") or 200),
            }
    return None


def _is_login_success(result: dict[str, Any]) -> bool:
    for item in _walk(result):
        if str(item.get("resultCode", "")) == "0000":
            return True
        if str(item.get("errcode", "")) == "0":
            return True
    return False
