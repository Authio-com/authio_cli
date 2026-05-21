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
# from source (works today)
go install github.com/tcast/authio_cli/cmd/authio@latest

# Phase 3.5: a Homebrew tap will land
# brew install tcast/tap/authio
```

## Quick start

```bash
authio login                              # device-code flow against the dashboard
authio dev                                 # local proxy on :8089 → live auth-core
authio import auth0 --file users.json      # bulk-import from an Auth0 export
authio logs tail                           # show how to query audit events
```

## Commands

### `authio login`

Runs the OAuth-style device-code flow:

1. Mints a `(user_code, device_code)` pair on the management-api.
2. Prints the code, opens the dashboard at `/cli/login?code=…` in your browser.
3. You approve in the dashboard → a fresh `sk_live_` key is minted on your project (named `cli:<code>`).
4. The CLI receives the secret on its next poll and stores it in `~/.authio/credentials.toml` (mode `0600`).

Pass `--no-browser` to skip the auto-open. Pass `--api-url https://...` to point at a non-default management-api.

### `authio dev`

Runs a local HTTP proxy on `:8089` that forwards every request to the configured auth-core. Pretty-prints every request/response with status colors. Great for SDK customers debugging integrations against the live alpha.

```bash
authio dev --port 9000 --target https://authioauth-core-production.up.railway.app
```

### `authio import auth0 --file users.json [--dry-run] [--profile name]`

Reads an Auth0 user-export (JSON array or NDJSON), POSTs each user to `/v1/users` on the management-api. Idempotent on `(project_id, email)` — re-running picks up where it left off via a `.authio-import.cursor` file next to the input.

Authio never imports password hashes. Existing users get a magic-link enrollment invitation on their first attempted sign-in.

`clerk`, `cognito`, `firebase`, `supabase` are stubbed and return a clear "not implemented yet" with a roadmap pointer.

### `authio logs tail`

Shows you the curl command to query audit events directly. Live streaming lands in Phase 3.5.

### `authio webhook listen <local-url>`

Documents the recommended `ngrok http` workflow until we wire a first-party tunnel.

### `authio version`

```bash
$ authio --version
authio 0.1.0-alpha.0
```

## Profiles

`~/.authio/credentials.toml` supports multiple profiles. Switch with `--profile <name>` on any command. The first `authio login` writes `[default]`.

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
- https://authiodocs-production.up.railway.app

## License

MIT
