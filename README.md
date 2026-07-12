<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/logo-dark.png">
    <img alt="Authio" src=".github/logo-light.png" width="220">
  </picture>
</p>

# authio (CLI)

The official Authio CLI — Stripe-quality DX for the platform.

## Install

```bash
# curl | sh — detects your OS/arch, downloads the latest release binary,
# and verifies its SHA-256 against the published checksums before installing.
curl -fsSL https://raw.githubusercontent.com/authio-com/authio_cli/main/scripts/install.sh | sh

# Homebrew
brew install authio-com/tap/authio

# from source (always works)
go install github.com/tcast/authio_cli/cmd/authio@latest
```

The installer drops the binary in `/usr/local/bin` (falling back to
`~/.local/bin` when that is not writable). Override with env vars:
`AUTHIO_VERSION=vX.Y.Z`, `AUTHIO_INSTALL_DIR=...`, `AUTHIO_REPO=owner/name`.

## Quick start

```bash
authio login                               # device-code flow against the dashboard
authio whoami                              # which environment + key am I using?
authio doctor                              # diagnose your local setup
authio listen --forward http://localhost:3000/webhooks   # stream events locally
authio dev                                 # local proxy on :8089 → live auth-core
authio import auth0 --file users.json      # bulk-import from an Auth0 export
```

## Commands

### `authio login`

Runs the OAuth-style device-code flow:

1. Mints a `(user_code, device_code)` pair on the management-api.
2. Prints the code, opens the dashboard at `/cli/login?code=…` in your browser.
3. You approve in the dashboard → a fresh `sk_live_` key is minted on your project (named `cli:<code>`).
4. The CLI receives the secret on its next poll and stores it in `~/.authio/credentials.toml` (mode `0600`).

Pass `--no-browser` to skip the auto-open. Pass `--api-url https://...` to point at a non-default management-api.

### `authio whoami`

Resolves the active profile, calls `GET /v1/projects/me`, and prints the
tenant, environment, key family (test/live) and the API it targets. Add
`--json` for machine-readable output.

```text
  Profile:      default
  Tenant:       Acme
  Environment:  Staging (My App — Staging)
  Key:          sk_test_…a1b2 (test key)
  Project ID:   proj_…  (environment ID; API field project_id)
  API:          https://authiomanagement-api-production.up.railway.app
```

### `authio doctor`

Runs a checklist over your local setup and exits non-zero if anything
fails (handy in CI: `authio doctor && deploy`). Add `--json` for
structured output, `--no-webhook-ping` to skip outbound reachability
probes, and `--repo owner/name` to check a fork for newer releases.

Checks:

- **cli version** — compares your build against the latest GitHub release.
- **credentials** — that the active key authenticates (`whoami`).
- **management-api / auth-core** — reachability + latency (health + JWKS).
- **key ↔ environment** — flags a `sk_live_` key pointed at a non-prod
  environment (or vice versa).
- **clock skew** — compares your clock to the server's `Date`; large skew
  breaks TOTP and webhook signature verification.
- **webhooks** — lists active endpoints, surfaces failure streaks, and
  (optionally) probes reachability from your machine.

### `authio env`

Surface and switch the active environment. Because an Authio API key is
**environment-scoped** (a `sk_test_` key only ever sees its non-prod
project's data), the CLI models environments as named credential
**profiles** — each profile holds one environment-scoped key.

```bash
authio env                 # show the active profile's environment
authio env list            # list profiles + their resolved environment
authio env use staging     # make a profile active for future commands
```

`authio env list` resolves each profile against `/v1/projects/me`:

```text
* default          Production   live   Acme
  staging          Staging      test   Acme
```

There is no `sk_`-authed route to enumerate a tenant's *other*
environments — that surface (`/v1/session/environments`) requires a
dashboard session — so `env` operates on what the API actually exposes to
a key: its own environment, per profile.

### `authio listen`

Forwards live events to a local HTTP endpoint — the Authio answer to
`stripe listen`.

```bash
authio listen --forward http://localhost:3000/webhooks
authio listen --forward http://localhost:3000/webhooks --events user.created,user.updated
authio listen --forward http://localhost:3000/webhooks --secret whsec_yourEndpointSecret
```

**How it works (v1):** the CLI polls the `sk_`-authed Events API
(`GET /v1/events`) and replays each new event to your local target as a
fully-formed Authio webhook — identical JSON envelope, an
`Authio-Signature` HMAC computed with the **exact** scheme the webhooks
worker uses, plus `Authio-Event-Id` / `Authio-Event-Action` headers.
Because it polls, deliveries arrive with up to one poll interval of
latency (`--interval`, default 2s) — great for local development, not a
production transport.

**Signature passthrough:** pass `--secret whsec_…` (a real endpoint's
signing secret, shown once at creation) to reproduce that endpoint's exact
signature, so your existing verification code runs unchanged locally. Omit
it and the CLI generates a throwaway secret and prints it — set that in
your local handler to verify HMAC.

Flags: `--forward <url>` (required), `--secret`, `--events a,b`,
`--interval <secs>`, `--replay <N>` (forward the N most recent existing
events on startup). Each delivery prints the event type, local response
status, and latency; Ctrl+C prints a delivered/failed summary.

### `authio dev`

Runs a local HTTP proxy on `:8089` that forwards every request to the configured auth-core. Pretty-prints every request/response with status colors. Great for SDK customers debugging integrations against the live alpha.

```bash
authio dev --port 9000 --target https://authioauth-core-production.up.railway.app
```

### `authio import auth0 --file users.json [--dry-run] [--profile name]`

Reads an Auth0 user-export (JSON array or NDJSON), POSTs each user to `/v1/users` on the management-api. Idempotent on `(project_id, email)` — re-running picks up where it left off via a `.authio-import.cursor` file next to the input.

Authio never imports password hashes. Existing users get a magic-link enrollment invitation on their first attempted sign-in.

Live importers are available for `auth0`, `clerk`, `cognito`, `firebase`, and `supabase` (via `authio migrate run --live`). File-based `--input` bundles work for every provider.

### `authio logs tail`

Shows you the curl command to query audit events directly. Live streaming lands in Phase 3.5.

### `authio webhook listen <local-url>` (legacy)

Documents the `ngrok http` workflow. Prefer **`authio listen`** above,
which forwards events to your local endpoint with no tunnel required.

### `authio orgs create`

```bash
authio orgs create --name Acme --slug acme --domain acme.com
```

Creates an organization via `POST /v1/organizations`. Optional `--json` for
machine-readable output.

### `authio webhooks create`

```bash
authio webhooks create --url https://api.example.com/webhooks/authio \
  --events user.created,session.created
```

Registers a webhook endpoint via `POST /v1/webhooks`. Defaults to `--events *`
when omitted. Optional `--org org_…`, `--description`, `--json`.

Distinct from the legacy `authio webhook listen` (ngrok helper) and from
`authio listen` (local event forwarder).

### `authio keys rotate`

```bash
authio keys rotate --name cli-rotated
```

Mints a replacement workspace `sk_` key, writes it to the active profile in
`~/.authio/credentials.toml`, then revokes the previous key.

### Redirect URIs / allowed origins

There is no CLI subcommand yet. Provision per-customer domains with the
Management API (`POST /v1/redirect-uris`, `POST /v1/allowed-origins`) using a
workspace `sk_` key — see
https://docs.authio.com/recipes/manage-with-api-key#multi-tenant-custom-domains.

### `authio version`

```bash
$ authio --version
authio 0.1.0-alpha.0
```

## Profiles

`~/.authio/credentials.toml` supports multiple profiles. Switch per-command with `--profile <name>`, or set a default with `authio env use <name>` (persisted in `~/.authio/config.toml`, separate from the secret-bearing credentials file). The first `authio login` writes `[default]`.

```toml
[default]
api_key = "sk_live_..."
project_id = "proj_..."
api_url = "https://authiomanagement-api-production.up.railway.app"
auth_core_url = "https://authioauth-core-production.up.railway.app"

[staging]
api_key = "sk_test_..."
project_id = "proj_staging_..."
```

## Source

- https://github.com/authio-com/authio_cli
- https://docs.authio.com

## License

MIT
