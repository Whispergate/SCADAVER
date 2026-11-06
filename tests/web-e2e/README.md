# SCADAver web E2E tests

These Playwright tests start SCADAver with `SCADAVER_TEST_LOOPBACK=1`. In that
mode the API exposes one synthetic adapter (`127.0.0.1/32`) and rejects every
non-loopback scan/probe request before any network operation begins.

From this directory, install the runner and browser once:

```powershell
npm install
npx playwright install chromium
npm test
```

The suite checks browser rendering, interface selection, the core protocol
catalog, front-end validation, and loopback-only API guards. It deliberately
does not run a protocol scan until that protocol's high-port simulator probe is
wired into the web API. Protocol agents should extend `web.spec.mjs` with a
simulator lifecycle fixture and successful read-only scan assertions.
