# VERIX OTP Platform

A free-first, private SMS receiving management platform for phone numbers the operator is authorized to control.

## Architecture

- Cloudflare Workers: API and static frontend hosting
- Cloudflare D1: users, sessions, assigned numbers, inbound messages, audit events
- Provider-neutral inbound webhook: connect a legitimate SMS provider that supports inbound SMS on numbers you own/control

## Safety and privacy

- This is a private inbox, not a public OTP-sharing directory.
- Customers can only see messages for numbers explicitly assigned to them.
- Super admins can manage users/numbers and view all messages.
- Do not use this service to bypass third-party verification, collect codes for accounts you do not own, or expose authentication codes publicly.
- Do not connect numbers without authorization or provider permission.
- Message contents may contain sensitive authentication codes. Restrict admin access and configure retention before production.

## Setup

1. Install Node.js 20+ and Wrangler:
   `npm install`
2. Create a D1 database:
   `npx wrangler d1 create verix-db`
3. Put the returned database ID in `wrangler.toml`.
4. Initialize the schema:
   `npm run db:init`
5. Set secrets:
   `npx wrangler secret put BOOTSTRAP_SECRET`
   `npx wrangler secret put INBOUND_WEBHOOK_SECRET`
6. Deploy:
   `npm run deploy`

The first admin is created once through `POST /api/admin/bootstrap` using the `x-bootstrap-secret` header. Set a strong secret first, call this endpoint once, then rotate/remove the bootstrap secret using Cloudflare dashboard after setup.

## API

- `POST /api/admin/bootstrap` — create the first super admin (one-time)
- `POST /api/auth/login` — sign in
- `POST /api/auth/logout` — sign out
- `GET /api/me` — current account
- `POST /api/admin/users` — create a customer (admin only)
- `POST /api/admin/numbers` — register a controlled number and optionally assign it
- `POST /api/inbound/sms` — provider webhook (requires `x-webhook-secret`)
- `GET /api/messages` — list messages visible to the signed-in user

Provider payload expected at the inbound endpoint:
`{ "from": "+8801...", "to": "+1...", "body": "Message text", "providerMessageId": "optional-id" }`

Adapt the webhook adapter to the chosen provider's signature and payload format before production. The shared secret is a starter integration guard, not a substitute for provider signature verification.

## Development

`npm run dev` starts Wrangler locally. Configure local D1 with the schema before testing.

## Status

Initial foundation. No SMS provider is bundled or activated; real inbound SMS requires a legitimate provider and numbers with inbound SMS capability.
