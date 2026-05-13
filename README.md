# authio (CLI)

The official Authio CLI — Stripe-quality DX. Login, scaffold projects, run a local
auth-core proxy with mock JWKS, tail logs, listen on local ports for webhook
deliveries, and bulk-import users from Auth0 / Clerk / Cognito / Firebase / Supabase.

## Install

```bash
brew install tcast/tap/authio       # Phase 3.5
go install github.com/tcast/authio_cli@latest
```

## Commands

- `authio login`
- `authio init`
- `authio dev`
- `authio logs tail`
- `authio webhook listen <local-url>`
- `authio import auth0|clerk|cognito|firebase|supabase --file users.json`

## License

MIT
