# Memact Access

Access checks who can do what.

It handles apps, users, consent, API keys, scopes, activity categories, feature
access, capture ingestion checks, and audit/usage records.

Access is the backend front door for Memact. It is not the capture engine,
meaning engine, schema engine, feature runtime, or memory store.

## What This Repo Owns

- App registration metadata.
- API key hashing, verification, and revocation.
- User consent and connection ids.
- Scope and category policy.
- Capture-event ingestion checks.
- Feature access checks.
- Schema and memory summary access checks.
- Audit and usage records.

## What This Repo Does Not Own

- Browser extension capture logic.
- Semantic inference.
- Schema packet formation.
- Durable memory ranking.
- Studio feature implementations.
- Archived Intent routes as a core product path.

## Product Flow

```text
Access checks
-> Capture receives
-> Inference understands
-> Schema organizes
-> Memory stores
-> Studio features run
-> Apps and users use results
```

Website manages Access records. Apps call Access before sending signals or
using Memact features.

## Routes

```text
GET  /health
GET  /v1/policy
POST /v1/access/verify
POST /v1/capture/events
GET  /v1/capture/events
GET  /v1/features
POST /v1/features/:featureId/run
GET  /v1/schemas
GET  /v1/memory
```

`POST /v1/intent/predict` is no longer a core route and returns `410`.

## Capture Events

Apps send capture events from their backend after permission:

```http
POST /v1/capture/events
Authorization: Bearer mka_your_private_key
Content-Type: application/json
```

```json
{
  "connection_id": "connection_id_from_consent",
  "event_type": "article_read",
  "category": "web:research",
  "payload": {
    "title": "Integration guide",
    "url": "https://example.com/docs"
  }
}
```

Access verifies the key, consent, scopes, and category before accepting the
event.

## Features

The default feature registry includes:

- `user-context-wiki`
- `cognitive-load`
- `research-map`

If Studio is not connected yet, feature runs fail clearly with
`feature_runtime_unavailable` instead of inventing output.

## Development

```powershell
npm install
npm run check
```

## License

See `LICENSE`.
