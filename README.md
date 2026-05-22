# Memact Access

Access checks who can do what.

It handles apps, users, consent, API keys, scopes, activity categories, feature
access, capture ingestion checks, and audit/usage records.

Access is the backend front door for Memact. It is not the capture engine,
meaning engine, schema engine, feature runtime, or memory store.

In this repo, "works" means Access can verify an app, accept permitted capture
events, list available features, enforce feature scopes, and return permitted
schema/memory summaries from its store. If a deeper runtime is not connected,
Access returns a clear error instead of pretending it produced a feature result.

For the playground flow, apps send permitted signals to Access. Access gates the
request, Capture records the activity, Schema and Memory prepare useful memory,
and Playground features can return personalization help back to the app.

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
- Playground feature implementations.
- Archived Intent routes as a core product path.

## Product Flow

```text
Access checks
-> Capture receives
-> Inference understands
-> Schema organizes
-> Memory stores
-> Playground features run
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

Accepted events are stored in the Access store today so the gateway can be
tested end to end. Capture remains the repo that owns capture normalization,
privacy skips, extension capture, and future capture storage adapters.

## Features

The default feature registry includes:

- `user-context-wiki` / Memory Wiki
- `cognitive-load`
- `research-map`

When Playground is available through `MEMACT_PLAYGROUND_PATH` or a sibling `playground`
folder, Access loads the feature and runs it. `MEMACT_STUDIO_PATH` still works as a compatibility fallback. If Playground is not connected,
feature runs fail clearly with `feature_runtime_unavailable` instead of
inventing output.

## Backend Reality Check

The backend is currently real in these places:

- API keys are hashed and checked.
- Consent and `connection_id` are checked before app access.
- Scopes and activity categories are enforced.
- Capture events can be accepted through `POST /v1/capture/events`.
- Sensitive payload fields are stripped before storage.
- Feature registry is returned through `GET /v1/features`.
- Feature runs require `feature:run`.
- Playground features run locally when the Playground runtime is available.
- Schema and memory summary routes require their read scopes.
- The old intent route is not silently used as core API.

The backend is intentionally not pretending in these places:

- Playground feature execution is not faked if the runtime is unavailable.
- Capture, Inference, Schema, and Memory stay separate repos instead of being
  copy-pasted into Access.
- Supabase remains an auth/storage integration path, not the product identity.

## Development

```powershell
npm install
npm run check
```

## License

See `LICENSE`.
