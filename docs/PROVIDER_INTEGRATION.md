# VERIX provider integration contract

VERIX uses a provider-independent inbound SMS contract. Provider credentials and webhook signing secrets must be stored as Cloudflare Worker secrets, never in D1, GitHub source, or browser code.

## Normalized inbound event

After verifying the provider's documented signature and timestamp/replay rules, an adapter maps its webhook into:

```json
{
  "providerMessageId": "provider-unique-message-id",
  "from": "+15551234567",
  "to": "+15557654321",
  "body": "Example inbound message"
}
```

The current generic `POST /api/inbound/sms` route is a staging boundary protected by `INBOUND_WEBHOOK_SECRET`. It is not a production provider adapter. Do not point a real provider at it until its signature scheme, retries, timestamp validation, idempotency, and payload mapping have been implemented and tested.

## Activation rules

1. Provider access must be approved by the provider for inbound SMS and the intended public/shared or private use.
2. Provider account is created as `pending`; no number is customer-visible.
3. Number inventory is created as `pending` with inbound disabled.
4. An adapter is implemented for the provider's official webhook and API.
5. Signature verification, replay protection, duplicate delivery, and delivery tests pass.
6. Only then may provider and number status be activated.

## Number models

- `public`: provider must explicitly permit shared public inbox use. Every authenticated customer can see messages. Never advertise it as private.
- `private`: one active customer assignment; messages are visible only to that customer and admins.
- Do not promise acceptance by third-party websites. Their policies and filtering determine whether they accept a number.
- Free trial credits are not permanent free number rental or guaranteed inbound SMS.
