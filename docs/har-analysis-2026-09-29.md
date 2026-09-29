# 95598 web login HAR analysis (2026-09-29)

This document records only protocol facts observed in the supplied browser HAR. It intentionally omits cookies, phone numbers, tokens, Tencent tickets, and other session material.

## Observed sequence

| Approx. time | Request | Observation |
|---|---|---|
| 12:05:49 | `POST /api/osg-open-uc0001/member/arg/010360007` | Pre-auth/login state request before Tencent Captcha appears |
| 12:05:49 | `GET turing.captcha.qcloud.com/cap_union_prehandle` | Tencent Captcha initialization |
| 12:05:49 | `GET .../cap_union_new_getcapbysig` | Captcha image material |
| 12:06:08 | `POST .../cap_union_new_verify` | Tencent verification succeeds (`errorCode=0`); returns `ticket` and `randstr` |
| 12:06:08 | `POST /api/osg-open-uc0001/member/arg/010360007` | Same State Grid pre-auth endpoint is called again after captcha |
| 12:06:21 | `POST /api/osg-uc0013/member/c4/f02` | State Grid auth/session transition |
| 12:06:22 | `POST /api/oauth2/outer/c02/f02` | OAuth key/session step |
| 12:06:22 | `POST /api/oauth2/oauth/authorize` | OAuth authorization step |
| 12:06:22 | `POST /api/oauth2/outer/getWebToken` | Exchanges authorization result for WebToken |
| 12:06:23+ | `POST /api/osg-open-*` | Authenticated account/business calls |

## Tencent Captcha

The HAR proves the browser is using Tencent Captcha rather than a locally implemented State Grid click-card widget. The final Tencent request returns `errorCode=0`, plus a `ticket` and `randstr`.

The integration should therefore treat Tencent Captcha as a **human-in-the-loop provider**. It should not implement OCR, OpenCV matching, or an LLM solver for this flow.

## Duplicate-looking OAuth requests

The HAR contains two `c02/f02`, two `authorize`, and two `getWebToken` calls. Their timestamps are separated by only tens of milliseconds. Since the user performed one login, these should be treated as frontend/concurrent duplicate work until proven otherwise; the integration should not assume they represent two user logins.

## Phone/SMS gap

No clearly named `sendSms` endpoint appears in the HAR. The encrypted State Grid request bodies prevent the plaintext schema from being read directly. The repeated `010360007` call immediately after successful Tencent verification is therefore a prime candidate for the state transition that carries the captcha result and/or triggers SMS delivery, but this is an inference and is intentionally not encoded as a guessed payload.

## OAuth result

After `getWebToken`, the browser sends authenticated requests using a `WEB.*` bearer token and the negotiated `keyCode`/`t` values. The token is session material and must never be committed to source control.

## Implementation consequence

The next production implementation should separate the flow into:

1. Tencent human captcha UI.
2. State Grid pre-auth state (`010360007`).
3. SMS verification.
4. OAuth authorization.
5. WebToken exchange.
6. Token persistence/refresh.
7. Account discovery and HA sensors.

Do not guess the encrypted phone/SMS request schema from endpoint names alone.
