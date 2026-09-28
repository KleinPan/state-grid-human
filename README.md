# state-grid-human

Home Assistant integration for State Grid (国家电网) that lets the user complete the web captcha manually instead of using an AI captcha solver.

## Status

Early prototype. This repository currently establishes the project structure and design direction. The next step is implementing the State Grid captcha/session flow and SMS login.

## Design

```text
Home Assistant
    |
    +-- request State Grid captcha
    |
    +-- open human captcha page
    |       |
    |       +-- user clicks requested icons in order
    |       |
    |       +-- submit click coordinates
    |
    +-- continue State Grid login
```

No vision LLM or captcha-solving service is required.

## References

- https://github.com/tiejiang29/state_grid
- https://github.com/Shaobor/Shaobo-Pocket-Carrier

## Disclaimer

This is an unofficial integration. Use it only with your own account and comply with the service's terms.
