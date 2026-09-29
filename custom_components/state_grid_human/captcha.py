"""Short-lived state for human-completed State Grid captcha challenges."""
from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Any


@dataclass(slots=True)
class CaptchaSession:
    flow_id: str
    login_key: str
    account: str
    password: str
    target_text: str = ""
    target_image: str = ""
    canvas: str = ""
    icons: list[str] = field(default_factory=list)
    width: int = 310
    height: int = 200
    created_at: float = field(default_factory=time.monotonic)

    def expired(self, ttl: float = 300.0) -> bool:
        return time.monotonic() - self.created_at > ttl


class CaptchaStore:
    """In-memory captcha store; credentials and captcha material are not persisted."""

    def __init__(self) -> None:
        self._items: dict[str, CaptchaSession] = {}

    def put(self, session: CaptchaSession) -> None:
        self._items[session.flow_id] = session

    def get(self, flow_id: str) -> CaptchaSession | None:
        item = self._items.get(flow_id)
        if item is None:
            return None
        if item.expired():
            self._items.pop(flow_id, None)
            return None
        return item

    def pop(self, flow_id: str) -> CaptchaSession | None:
        return self._items.pop(flow_id, None)


STORE = CaptchaStore()


def normalize_clicks(
    value: Any, *, width: int = 310, height: int = 200
) -> list[dict[str, int]]:
    """Validate clicks against the source captcha dimensions."""
    if not isinstance(value, list) or not 1 <= len(value) <= 10:
        raise ValueError("invalid click list")

    result: list[dict[str, int]] = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("invalid click item")
        x, y = item.get("x"), item.get("y")
        if not isinstance(x, int) or not isinstance(y, int):
            raise ValueError("invalid click coordinate")
        if not 0 <= x < width or not 0 <= y < height:
            raise ValueError("click outside captcha")
        result.append({"x": x, "y": y})
    return result
