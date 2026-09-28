"""Home Assistant config flow for the human captcha integration."""
from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .captcha import CaptchaSession, STORE, normalize_clicks
from .client import StateGridClient
from .const import CAPTCHA_VIEW, DOMAIN


class StateGridHumanConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Configure a State Grid account while keeping captcha interaction human."""

    VERSION = 1

    def __init__(self) -> None:
        self._account = ""
        self._password = ""
        self._client: StateGridClient | None = None
        self._captcha_login_key = ""

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        """Collect credentials and request the reference password captcha."""
        errors: dict[str, str] = {}
        if user_input:
            self._account = str(user_input["account"]).strip()
            self._password = str(user_input["password"])
            session = async_get_clientsession(self.hass)
            self._client = StateGridClient(session)
            try:
                await self._client.negotiate_key()
                result = await self._client.get_password_captcha(self._account, self._password)
                captcha = _extract_captcha(result)
                if captcha is None:
                    errors["base"] = "captcha_response_invalid"
                else:
                    self._captcha_login_key = captcha["login_key"]
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
                    return self.async_show_external_step(
                        step_id="captcha",
                        url_path=f"{CAPTCHA_VIEW}/{self.flow_id}",
                        description_placeholders={"url": f"{CAPTCHA_VIEW}/{self.flow_id}"},
                    )
            except Exception:
                errors["base"] = "cannot_connect"

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required("account"): str,
                    vol.Required("password"): str,
                }
            ),
            errors=errors,
        )

    async def async_step_captcha(self, user_input: dict[str, Any] | None = None):
        """Receive the coordinates from the human captcha page."""
        if not user_input:
            return self.async_show_external_step(
                step_id="captcha",
                url_path=f"{CAPTCHA_VIEW}/{self.flow_id}",
                description_placeholders={"url": f"{CAPTCHA_VIEW}/{self.flow_id}"},
            )

        session = STORE.get(self.flow_id)
        if session is None or self._client is None:
            return self.async_abort(reason="captcha_expired")

        try:
            clicks = normalize_clicks(user_input.get("captcha_clicks"))
            code = "|".join(f"{item['x']},{item['y']}" for item in clicks)
            result = await self._client.click_card(
                session.account, session.password, session.login_key, code
            )
        except Exception:
            return self.async_abort(reason="cannot_connect")

        if not _is_login_success(result):
            STORE.pop(self.flow_id)
            return self.async_abort(reason="captcha_rejected")

        STORE.pop(self.flow_id)
        return self.async_create_entry(
            title=f"国家电网 {self._account}",
            data={"account": self._account},
        )


def _walk(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


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
