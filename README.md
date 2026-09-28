# state-grid-human

Home Assistant integration for State Grid (国家电网) that lets the user complete the web captcha manually instead of using an AI captcha solver.

## Current status

The repository now contains the first end-to-end **human captcha prototype**:

- encrypted State Grid HTTP transport scaffold
- f05 password-login captcha request
- HA Config Flow external captcha step
- responsive browser captcha page
- mouse/touch coordinate capture in the captcha's native image coordinates
- f07 click-card payload generation/submission
- in-memory captcha sessions with a five-minute TTL
- no vision LLM or automatic captcha solving

The final production flow still needs the current **mobile/SMS login API** and real-world verification against a live State Grid account. The current prototype intentionally exercises the password-login captcha path because that is the protocol exposed by the reference implementation.

## Architecture

```text
Home Assistant Config Flow
        |
        +-- State Grid f05
        |       |
        |       +-- captcha images / loginKey
        |
        +-- external human captcha page
        |       |
        |       +-- user clicks target icons in order
        |       |
        |       +-- x,y|x,y|x,y
        |
        +-- State Grid f07
                |
                +-- captcha accepted
```

## What remains

1. Verify the SM2/SM4 compatibility layer against a live f05 response.
2. Confirm the exact captcha response field mapping on the current 95598 gateway.
3. Capture and implement the current web **phone + SMS login** API.
4. Persist/refresh the resulting access and refresh tokens.
5. Add electricity-account discovery and HA sensors.

## What the user needs to provide

For the next stage, a single redacted browser network capture is the most useful input:

1. Open 95598 in a desktop browser.
2. Start phone-number login.
3. Enter the captcha and complete it manually.
4. Enter the SMS code and finish login.
5. Export the relevant requests as HAR, or provide screenshots/text of the request URLs, headers and JSON bodies.
6. Remove phone numbers, cookies, Authorization headers, tokens and other personal secrets before sharing.

A successful capture lets the project switch from the current password-login prototype to the intended phone + human-captcha + SMS flow.

## References

- https://github.com/tiejiang29/state_grid
- https://github.com/Shaobor/Shaobo-Pocket-Carrier

## Disclaimer

This is an unofficial integration. Use it only with your own account and comply with the service's terms.
