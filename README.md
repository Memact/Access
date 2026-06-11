# Memact Access

Access checks who can do what.

It handles apps, users, consent, API keys, scopes, activity categories, feature
access, capture ingestion checks, and audit/usage records.

Access is the backend front door for Memact. It is not the capture engine,
meaning engine, context engine, feature runtime, or memory store.

In this repo, "works" means Access can verify an app, accept permitted capture
events, list available features, enforce feature scopes, and return permitted
context/memory summaries from its store. If a deeper runtime is not connected,
Access returns a clear error instead of pretending it produced a feature result.

For the playground flow, apps send permitted signals to Access. Access gates the
request, Context and Memory prepare useful memory,
and Playground features can return personalization help back to the app.

## What This Repo Owns

- App registration metadata.
- API key hashing, verification, and revocation.
- User consent and connection ids.
- Scope and category policy.
- Capture-event ingestion checks.
- Feature access checks.
- Context and memory summary access checks.
- Audit and usage records.

## What This Repo Does Not Own

- Browser extension capture logic.
- Semantic inference.
- Context proposal formation.
- Durable memory ranking.
- Playground feature implementations.
- Archived Intent routes as a core product path.

## Product Flow

```text
Access checks
-> Context organizes
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
GET  /v1/context
GET  /v1/memory
GET  /v1/credits
```

`/v1/schemas` still works as a compatibility alias for older SDKs and PRs.

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

## Context proposals and credits

Apps can send either:

- raw signals, such as a music replay, workout completion, or saved product
- context proposals, such as "prefers strength workouts", backed by evidence

Access checks the app key, connection, scopes, and categories before creating a
pending Wiki proposal. Raw signals earn a smaller app credit bonus because
Memact still needs to shape them. Context proposals with evidence earn a larger
bonus. Reading allowed context spends credits.

Credits are simple developer-side accounting, not a user-facing billing system.
Users mainly see the Wiki: what apps know, what they propose, and what the user
can accept, edit, reject, or delete.

## Features

The default feature registry includes:

- `user-context-wiki` / Memory Wiki
- media/articles category support
- community/bot category support
- `cognitive-load`
- `research-map`

When Playground is available through `MEMACT_PLAYGROUND_PATH` or a sibling `playground`
folder, Access loads the feature and runs it. If Playground is not connected,
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
- Context and memory summary routes require their read scopes.
- The old intent route is not silently used as core API.

The backend is intentionally not pretending in these places:

- Playground feature execution is not faked if the runtime is unavailable.
- Context and Memory stay separate repos instead of being
  copy-pasted into Access.
- Supabase remains an auth/storage integration path, not the product identity.

## Development

```powershell
npm install
npm run check
```

## License

See `LICENSE`.
