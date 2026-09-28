"""State Grid Human integration."""

from __future__ import annotations

from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .http import CaptchaView


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the integration."""
    hass.data.setdefault(DOMAIN, {})
    hass.http.register_view(CaptchaView)
    return True


async def async_setup_entry(hass: HomeAssistant, entry) -> bool:
    """Set up a config entry."""
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = entry.data
    return True


async def async_unload_entry(hass: HomeAssistant, entry) -> bool:
    """Unload a config entry."""
    hass.data[DOMAIN].pop(entry.entry_id, None)
    return True
