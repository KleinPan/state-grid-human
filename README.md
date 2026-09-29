# state-grid-human

Home Assistant integration research project for State Grid (国家电网) that keeps captcha completion in the user's hands instead of using a vision LLM.

## Current status

The repository contains a working prototype for the **password-login captcha** path and the protocol/session scaffolding needed for a human captcha step.

A real 95598 browser HAR was also analyzed. The current web login is **not the same protocol as the older password-login path** exposed by the reference `state_grid` project.

### Confirmed from the supplied HAR

The current 95598 web flow uses Tencent Captcha:

```text
95598 login page
    |
    +-- /api/osg-open-uc0001/member/arg/010360007
    |
    +-- Tencent Captcha
    |      |
    |      +-- cap_union_prehandle
    |      +-- cap_union_new_getcapbysig
    |      +-- cap_union_new_verify
    |      |
    |      +-- returns ticket + randstr
    |
    +-- /api/osg-open-uc0001/member/arg/010360007
    |
    +-- /api/osg-uc0013/member/c4/f02
    |
    +-- /api/oauth2/outer/c02/f02
    +-- /api/oauth2/oauth/authorize
    +-- /api/oauth2/outer/getWebToken
    |
    +-- authenticated business APIs
```

The HAR contains a successful Tencent verification response with `errorCode=0`, `ticket`, and `randstr`. This means the project should **not attempt to reproduce or solve the Tencent challenge**. The intended design is to let the user complete the official captcha in a browser.

The HAR also shows two very closely spaced OAuth request sequences. They occur within tens of milliseconds, so they are treated as frontend/concurrency behavior rather than evidence that the user logged in twice.

The first authenticated State Grid business calls after `getWebToken` include account/user discovery endpoints such as `osg-open-uc0001/member/c9/f02`.

## Important limitation

The supplied HAR encrypts the State Grid request bodies. It therefore proves the request sequence and endpoint relationships, but it does **not** by itself reveal the plaintext schema of the phone/SMS login request.

In particular, the capture does not expose a clearly named `sendSms` endpoint. The same `member/arg/010360007` endpoint is called before and after Tencent verification, which strongly suggests that the login/pre-auth state is advanced there, but the exact encrypted payload must not be guessed.

The next implementation target is therefore:

1. reproduce the current State Grid key/session negotiation;
2. decode the encrypted `010360007` response with the current gateway crypto;
3. identify the plaintext fields containing the phone/Tencent ticket state;
4. implement phone + human captcha + SMS login;
5. exchange the OAuth authorization result for `WebToken`;
6. persist/refresh authentication state;
7. add account/electricity sensors.

## Architecture

```text
Home Assistant Config Flow
        |
        +-- current phone-login flow
        |       |
        |       +-- official Tencent captcha
        |       |       |
        |       |       +-- user completes challenge
        |       |
        |       +-- State Grid pre-auth/session
        |       +-- SMS verification
        |       +-- OAuth authorization
        |       +-- WebToken
        |
        +-- authenticated State Grid client
                |
                +-- account discovery
                +-- balance / bill / daily usage
                +-- HA sensors
```

## Design principles

- No captcha-solving AI.
- No OpenCV captcha solver.
- Prefer the official Tencent captcha UI whenever the current web flow permits it.
- Keep captcha/session material in memory and expire it quickly.
- Do not commit personal HAR files, cookies, authorization headers, phone numbers, SMS codes, or tokens.
- Do not hard-code personal credentials or captured authentication tokens.

## References

- https://github.com/tiejiang29/state_grid
- https://github.com/Shaobor/Shaobo-Pocket-Carrier

## Disclaimer

This is an unofficial integration/research project. Use it only with your own account and comply with the service's terms.
