# pi-router-restarter

[![CI](https://github.com/ilteoood/pi-router-restarter/actions/workflows/ci.yml/badge.svg)](https://github.com/ilteoood/pi-router-restarter/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D24-5FA04E)](package.json)

A [Pi](https://github.com/earendil-works/pi) extension that reconnects the GPON WAN of a TP-Link router so the ISP hands out a fresh public IP address.

It registers a single slash command:

```text
/new-ip
```

which logs into the router over the local network, drops the PPPoE session on the GPON WAN, waits for it to go down, brings it back up, waits for it to re-establish, and reports the address change:

```text
WAN IP address refreshed 81.32.14.7 -> 93.44.201.18
```

This is useful when your ISP assigns a dynamic public address and you need a different one — to bypass a network-level block, refresh a leaked port mapping, or make a service that whitelists your IP reachable again.

---

## Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [How it works](#how-it-works)
- [Using the client as a library](#using-the-client-as-a-library)
- [Repository layout](#repository-layout)
- [Development](#development)
- [Continuous integration](#continuous-integration)
- [Security notes](#security-notes)
- [License](#license)

---

## Requirements

| Requirement | Details |
| --- | --- |
| **Node.js** | 24 or later (`engines.node: ">=24"`) |
| **Pi** | The [coding agent runtime](https://github.com/earendil-works/pi) that loads the extension |
| **Router** | A TP-Link router reachable over the LAN that exposes the `cgi_gdpr` API family (`/cgi/getGDPRParm`, `/cgi_gdpr`) and the `DEV2_ADT_WAN` / `ACT_PPP_CONN` operations |
| **Connection** | The WAN under test must be a GPON/PON WAN (the code selects the connection whose `accessMode` is `PON`) |

Pi itself is installed separately:

```bash
curl -fsSL https://pi.dev/install.sh | sh
```

The extension talks to the router over HTTPS on the LAN. It never reaches the internet to do its job: the only traffic is to the router itself.

## Installation

Install it as a Pi package from GitHub:

```bash
pi install git:github.com/ilteoood/pi-router-restarter
```

Or try it for a single session without adding it to your settings:

```bash
pi -e git:github.com/ilteoood/pi-router-restarter
```

Alternatively, clone the repository and point Pi at the extension file directly:

```bash
git clone https://github.com/ilteoood/pi-router-restarter.git
cd pi-router-restarter
npm install
pi --extension ./src/extension.ts
```

Pi loads the extension through the `pi.extensions` manifest in `package.json`, which points at `src/extension.ts`. No build step is needed — Pi executes the TypeScript source directly, and `npm install` only fetches the runtime dependency the client needs to parse cookies.

To uninstall:

```bash
pi remove git:github.com/ilteoood/pi-router-restarter
```

## Configuration

The router credentials are read from the environment when the command runs:

| Variable | Meaning |
| --- | --- |
| `TPLINK_USERNAME` | Web UI user name of the router |
| `TPLINK_PASSWORD` | Web UI password of the router |

Both must be set and non-empty, otherwise the command fails with
`TPLINK_USERNAME and TPLINK_PASSWORD must both be set`.

```bash
export TPLINK_USERNAME=admin
export TPLINK_PASSWORD='your-password'
```

Keep them in your shell profile or secret manager rather than in the repository. Nothing is written to disk by the extension, and the credentials are never sent anywhere except to your own router.

## Usage

Inside a Pi session, run:

```text
/new-ip
```

The command performs the whole cycle on its own and reports the outcome as a notification:

- **Success** — `WAN IP address refreshed <old> -> <new>`
- **Failure** — the error message, for example `Router rejected "/cgi/login" with status 403` or `WAN connection on stack 0,0,0,0,0,0 stayed Disconnected for 60000 ms`

The whole operation takes a few seconds plus the ISP's redial time; the client gives up waiting for the connection to settle after 60 seconds.

## How it works

The router's web UI drives an internal API whose payloads are encrypted and signed. This extension speaks that API directly instead of scraping the HTML dashboard.

### 1. Handshake

A plain `POST /cgi/getGDPRParm` returns a small script carrying the parameters needed for the session:

```js
var nn = "<RSA modulus, hex>";
var ee = "<RSA exponent, hex>";
var seq = "<sequence counter>";
```

`nn` and `ee` become the router's public key, `seq` becomes the base offset for the request position counter.

### 2. Session keys

The client generates a random AES-128-CBC session from 8 random bytes for the key and 8 for the IV. A second value, `h`, is the MD5 hash of `username + password` and acts as a signature shared by every request.

### 3. Signed and encrypted requests

Every API call is wrapped in the same envelope. The request is serialized to JSON, terminated with `\r\n`, encrypted with AES-128-CBC and base64-encoded. The signature is computed over the position counter — the handshake sequence plus the length of the ciphertext — using the router's RSA key with raw (unpadded) encryption:

```text
sign=<hex RSA signature>
data=<base64 ciphertext>
```

The envelope is posted to `/cgi_gdpr?9`; the response body is AES-encrypted and decrypted with the same session.

The login request additionally folds the session key and IV into the signed material (`key=...&iv=...&h=...&s=...`), which is what binds the session to the router's key.

### 4. Authentication

Credentials travel base64-encoded in a `/cgi/login` call with `Action: 1`. The router answers with a script whose `$.ret` code says whether the login was accepted. A successful login yields a `JSESSIONID` cookie and a session token, which the client then picks up from the dashboard page and sends back as the `TokenID` header on every subsequent request.

### 5. Reading and changing the WAN

Two operations drive the router state:

| Operation | Purpose |
| --- | --- |
| `gl` + `DEV2_ADT_WAN` | List the WAN connections, each with its `stack`, `accessMode`, `connStatusV4` and `connIPv4Address` |
| `op` + `ACT_PPP_DISCONN` / `ACT_PPP_CONN` | Tear down and restore the PPPoE session on a given `stack` |

The client picks the connection with `accessMode === "PON"`, disconnects it, polls until `connStatusV4` is no longer `Connected`, reconnects it, and polls until it is `Connected` again — one poll per second.

### 6. Transport

Requests are written directly onto a TLS socket with `node:tls`, and the response is parsed by hand. That is deliberate: the router answers with self-signed certificates and with HTTP framing that is not always conventional (bodies that arrive chunked, and occasionally without a status line at all). A hand-rolled layer keeps the client tolerant of those quirks, and `src/http-response.ts` decodes chunked bodies and collects `Set-Cookie` headers.

## Using the client as a library

The extension is a thin wrapper around `TpLinkGdprClient`, which is exported for direct use:

```typescript
import { TpLinkGdprClient } from 'pi-router-restarter';

const client = new TpLinkGdprClient({
  username: process.env.TPLINK_USERNAME!,
  password: process.env.TPLINK_PASSWORD!,
  baseUrl: 'https://192.168.1.1'
});

await client.login();
const connection = await client.reconnectGponWan();
console.log(connection.connIPv4Address);
```

### API

| Member | Description |
| --- | --- |
| `new TpLinkGdprClient(options)` | `options` carries `username`, `password` and an optional `baseUrl` (default `https://192.168.1.1`, trailing slash trimmed) |
| `login()` | Performs the handshake, the login exchange and the session-token retrieval |
| `listWanConnections()` | Returns every WAN connection reported by the router |
| `gponWan()` | Returns the PON WAN connection, or throws when there is none |
| `operate(oid, data)` | Runs a single router operation |
| `disconnectGponWan()` / `connectGponWan()` | Single-step control of the GPON WAN |
| `reconnectGponWan(timeoutMs = 60_000)` | Full disconnect/reconnect cycle, returns the re-established connection |
| `RouterError` | Error type thrown for every failure surfaced by the client |

## Repository layout

```text
.
├── src/
│   ├── extension.ts           Pi extension: registers the /new-ip command
│   ├── index.ts               Public entry point of the package
│   ├── tp-link-gdpr-client.ts Router client: handshake, login, WAN operations
│   ├── gdpr-crypto.ts         AES-128-CBC session, MD5 hashing, raw RSA signing
│   ├── http-response.ts       Minimal HTTP/1.1 response parser (headers, cookies, chunked bodies)
│   ├── router-error.ts        RouterError, the error type of the package
│   └── utils.ts               Base64 encoding and script parsing helpers
├── test/
│   ├── gdpr-crypto.test.ts    Hashing, AES round-trip, raw RSA block splitting
│   ├── http-response.test.ts  Response parsing and chunked decoding
│   └── utils.test.ts          Base64 and script-assignment parsing
├── .github/
│   ├── workflows/ci.yml       Typecheck and test on every pull request
│   └── dependabot.yml         Weekly npm and GitHub Actions updates
├── package.json               Package manifest and Pi extension manifest
└── tsconfig.json              Strict TypeScript configuration
```

## Development

```bash
npm install
npm run typecheck   # tsc --noEmit
npm test            # node --test
```

Node 24 runs the TypeScript tests natively through type stripping, so there is no build or transpile step in the development loop.

The TypeScript configuration is deliberately strict — `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `noImplicitOverride`, `noFallthroughCasesInSwitch` and `verbatimModuleSyntax` are all on.

The test suite covers the pure logic: the cryptographic primitives, the HTTP response parser and the script parsing helpers. Nothing in the suite touches a real router, so `npm test` is safe to run anywhere.

## Continuous integration

`.github/workflows/ci.yml` runs on every pull request against Node 24: it installs the locked dependencies with `npm ci`, then runs the typecheck and the test suite.

`.github/dependabot.yml` checks the npm dependencies and the GitHub Actions weekly, grouping minor and patch updates into a single pull request while leaving major bumps for individual review.

## Security notes

- **The extension runs inside Pi** with the permissions of the Pi process. Only load it from sources you trust.
- **Credentials stay on the machine.** They are read from the environment, sent only to the router on your LAN, and never logged or persisted by this code.
- **TLS verification is disabled** for the router connection, because consumer routers ship self-signed certificates that cannot be validated against a public CA. The traffic therefore stays encrypted but is not authenticated. It is only safe because the destination is a router on your own LAN — do not point the client at a host you do not control.
- **The router's own admin credentials are enough to re-establish the WAN.** Treat the web UI account as privileged.

## License

[MIT](LICENSE) © 2026 Matteo Pietro Dazzi
