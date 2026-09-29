"""Current 95598 browser phone-login flow notes and state types.

The supplied 2026-09-29 browser HAR establishes these endpoints, but the
request bodies are encrypted.  This module deliberately does not invent the
plaintext payload schema.  It provides the stable endpoint map and state
objects so the real payload can be added after the gateway crypto is verified.
"""
from __future__ import annotations

from dataclasses import dataclass

BASE = "https://www.95598.cn/api"

# Current web login endpoints observed in the supplied HAR.
PRE_AUTH_API = "/osg-open-uc0001/member/arg/010360007"
PRE_OAUTH_API = "/osg-uc0013/member/c4/f02"
OAUTH_KEY_API = "/oauth2/outer/c02/f02"
OAUTH_AUTHORIZE_API = "/oauth2/oauth/authorize"
WEB_TOKEN_API = "/oauth2/outer/getWebToken"

# Tencent Captcha endpoints are intentionally represented as a provider, not
# as a captcha solver.  The official widget returns ticket/randstr after the
# user completes the challenge.
TENCENT_VERIFY_API = "https://turing.captcha.qcloud.com/cap_union_new_verify"


@dataclass(slots=True)
class TencentCaptchaResult:
    """Result returned by Tencent after the user completes the captcha."""

    ticket: str
    randstr: str


@dataclass(slots=True)
class PhoneLoginState:
    """State that must survive the human captcha step."""

    phone: str
    captcha: TencentCaptchaResult | None = None
    authorize_code: str | None = None
    web_token: str | None = None


def endpoint(path: str) -> str:
    """Build an absolute 95598 API URL."""
    return f"{BASE}{path}"
