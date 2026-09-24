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
4. The CLI receives the secret on its next poll and stores it atomically in `~/.authio/credentials.toml` (mode `0600`).

Login uses Authio's hosted production management API by default. Pass
`--no-browser` to skip the auto-open, or `--profile <name>` to save into a
named profile without replacing `[default]`. Local development is opt-in via
`--dev` or `AUTHIO_CLI_DEV=1`; explicit endpoint overrides are available as
`--api-url` and `--auth-core-url`.

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
  API:          https://api.authio.com
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
authio dev --port 9000 --target https://identity.authio.com
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

### `authio domains`

```bash
authio domains list
authio domains create --domain auth.example.com
authio domains verify --id dom_…
authio domains branding --id dom_… --display-name Acme --color '#112233'
```

Uses the secret key's project (`POST /v1/custom-domains` and friends). Pro
and enterprise plans also register the Cloudflare certificate. There is no
project-id flag. Add `--json` for the API body, including DNS records.

### `authio redirects`

```bash
authio redirects list
authio redirects create --uri https://app.example.com/callback --kind oauth_callback
```

### `authio mcp`

Stdio MCP server (newline JSON-RPC) for `whoami`, custom domains, domain
branding, and redirect URIs. It uses the same secret key as the other
commands and never accepts a dashboard session.

```json
{ "mcpServers": { "authio": { "command": "authio", "args": ["mcp"] } } }
```

### `authio keys rotate`

```bash
authio keys rotate --name cli-rotated
```

Mints a replacement workspace `sk_` key, writes it to the active profile in
`~/.authio/credentials.toml`, then revokes the previous key.

### `authio clearance` — local sidecar for Authio Clearance

[Clearance](https://docs.authio.com/clearance) judges every tool call an AI
agent makes — **cleared / needs clearance / denied** — against policy that
lives in Authio. Hosted tools (Valet-backed HubSpot, GitHub, Slack, …) are
served by `clearance.authio.com` directly. Tools that only exist on a
developer's machine — shell commands, stdio MCP servers — cannot be hosted,
so the sidecar wraps them: it asks Clearance for a verdict before every
call and records the result centrally. **The sidecar holds no policy of its
own.**

```sh
authio clearance login  --agent agt_…     # sign in as the agent's Connect client
authio clearance init   --agent agt_…     # print the MCP config to paste
authio clearance serve  --agent agt_…     # stdio MCP server (run by your MCP client)
authio clearance explain --agent agt_…    # the agent's resolved policy chain
```

`login` runs OAuth authorization-code + PKCE on a loopback redirect
(`http://127.0.0.1:<port>/callback`, RFC 8252) against auth-core as the
agent's DCR client — register that redirect on the client (pass `--port` to
keep it stable) — with scopes `tools:read tools:call` and
`resource=https://clearance.authio.com`. It saves a rotating refresh token in
`~/.authio/clearance/<agent>.json` (mode 0600) and renews silently; when a
refresh is rejected you are told to log in again. The agent's `client_id`
and project are read from your `authio login` profile via
`GET /v1/session/clearance/agents/:id`, or passed with `--client-id` /
`--project`.

`serve` exposes, as one stdio MCP server:

| tool | judged as | runs |
|---|---|---|
| everything the hosted agent lists (`valet.<provider>.request`, `clearance.await_approval`, …) | inside `tools/call` on clearance.authio.com | hosted — proxied verbatim |
| `exec.run {command, args, cwd?, timeout_ms?}` | `POST /v1/agents/{id}/evaluate` provider `exec`, tool `argv[0]`, policy targets `exec/<argv0>` and `exec:<command args>` | locally: no shell, argv verbatim, cwd confined to the launch directory, output capped at 1 MiB, timeout ≤ 120 s, child env = PATH + HOME only |
| `<provider>.<tool>` for each stdio server under `clearance.providers` | provider `mcp`, tool `<provider>/<tool>` | forwarded to the child process (spawned on first use, env scrubbed + explicit `env`) |

A `denied` or `needs_clearance` verdict is returned to the client as an
`isError` result with `_meta` (`verdict`, `reason_code`, `approval_id`,
`expires_at`) — never as a JSON-RPC error — so the agent can call
`clearance.await_approval` and retry. `initialize` may carry `_meta.intent`;
it is stored on the Clearance session and attached to every verdict.

Local providers go in `authio.yaml` (airlock-compatible shape); their
*policy* goes in the same file's `clearance:` block. `authio check` dry-runs
the block against `POST /v1/clearance/import` (the workspace API-key
surface — same `sk_...` auth as every other resource in this file; the
Clearance engine validates it and reports what would change — matched by
profile/agent *name*, so an already-existing profile always shows as an
update even with no content change); `authio apply` imports it — additive,
and unbound agents (named in the file, no matching Connect client id yet)
are a warning in the plan, not a silent no-op or a hard failure:

```yaml
clearance:
  providers:
    filesystem:
      type: stdio
      command: npx
      args: ["-y", "@modelcontextprotocol/server-filesystem", "/workspace"]
      env: { LOG_LEVEL: warn }
    exec: builtin
  profiles:
    developer:
      allow: ["valet/github/GET:*", "mcp/filesystem/read_*"]
      ask:   ["mcp/filesystem/write_*", "exec:git push*"]
      deny:  ["mcp/filesystem/delete_*", "exec:rm -rf *", "exec:sudo *"]
  agents:
    dev-helper:
      profile: developer
```

Endpoint overrides: `AUTHIO_CLEARANCE_URL` / `--clearance-url`,
`AUTHIO_AUTH_CORE_URL` / `--auth-core-url`, `AUTHIO_API_URL` / `--api-url`.

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

`~/.authio/credentials.toml` supports multiple profiles. Create or update one
with `authio login --profile <name>`, switch per-command with `--profile
<name>`, or set a default with `authio env use <name>` (persisted in
`~/.authio/config.toml`, separate from the secret-bearing credentials file).
Login writes `[default]` only when `--profile` is omitted.

```toml
[default]
api_key = "sk_live_..."
project_id = "proj_..."
api_url = "https://api.authio.com"
auth_core_url = "https://identity.authio.com"

[staging]
api_key = "sk_test_..."
project_id = "proj_staging_..."
```

## Source

- https://github.com/authio-com/authio_cli
- https://docs.authio.com

## License

MIT
