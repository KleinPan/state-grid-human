# state-grid-human

Home Assistant integration for State Grid (国家电网) with **human-completed captcha**. No captcha-solving AI or OpenCV solver is used.

## Current testable milestone: v0.4.0

The repository now contains a complete **password-login authentication path** based on the older State Grid Web gateway protocol:

```text
HA Config Flow
    |
    +-- account + password
    |
    +-- State Grid key/session negotiation
    |
    +-- c44/f05 captcha
    |       |
    |       +-- HA opens only a small captcha page
    |       +-- user clicks the requested images
    |
    +-- c44/f07 human captcha submission
    |
    +-- OAuth /authorize
    |
    +-- OAuth /getWebToken
    |
    +-- Config Entry created with returned auth state
```

The current implementation is deliberately limited to the password-login path until the newer phone/SMS protocol is fully identified. This gives us a clean real-device checkpoint without guessing encrypted request fields.

## Real-device test

1. In Home Assistant, add this GitHub repository as a **custom HACS repository** with category `Integration`, or manually copy `custom_components/state_grid_human` into the HA `custom_components` directory.
2. Restart Home Assistant.
3. Go to **Settings → Devices & services → Add integration**.
4. Search for **国家电网（人工验证码）** / **State Grid Human**.
5. Enter your own State Grid account and password.
6. HA will request the captcha from State Grid.
7. A small authenticated HA captcha page is opened; **only the captcha page is shown, not the 95598 login website**.
8. Click the requested images in order and press **确定**.
9. The integration submits the human result, performs the OAuth authorization-code exchange, and requests the WebToken.
10. A successful login creates the Config Entry.

### What success looks like

The Config Entry is created only after both of these conditions are true:

- the captcha/login response reports `resultCode=0000`;
- OAuth returns an `access_token`.

If either step fails, the flow is aborted rather than creating a fake/partial login entry.

## Important: current web login vs legacy Web gateway

The supplied 2026-09-29 browser HAR showed a newer web flow using Tencent Captcha followed by:

```text
member/arg/010360007
    ↓
Tencent Captcha
    ↓
member/c4/f02
    ↓
OAuth c02/f02
    ↓
OAuth authorize
    ↓
getWebToken
```

That flow is **not silently treated as identical** to the older `c44/f05 → c44/f07 → OAuth` flow. The encrypted phone/SMS payload has not been guessed or fabricated. The next milestone is to add the newer phone/SMS flow while keeping the human captcha requirement.

## Security / behavior

- No captcha-solving AI.
- No OpenCV captcha solver.
- The user performs the captcha challenge themselves.
- Captcha material and credentials used during Config Flow are kept in memory and the captcha session expires after five minutes.
- Personal HAR files, cookies, authorization headers, phone numbers, SMS codes and personal tokens must never be committed.
- Use the integration only with an account you are authorized to access.

## References

- https://github.com/tiejiang29/state_grid
- https://github.com/Shaobor/Shaobo-Pocket-Carrier

## Disclaimer

Unofficial integration/research project. Service-side behavior and authentication protocols may change at any time.
