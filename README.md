# Memact Access

Access checks who can do what.

It handles apps, users, consent, API keys, scopes, categories, memory
suggestions, allowed memory reads, and audit/usage records.

Access is the backend front door for Memact. It is not the Context engine, the
Wiki UI, or the durable Memory store.

## Product Flow

```text
App suggests memory or sends specific app details
-> Access checks permission
-> Context gives the app input a safe shape
-> Yourself shows it to the user
-> User accepts, edits, rejects, or deletes
-> Memory stores what survives
-> SDK lets apps read only allowed memory
```

Apps should not start from zero, and they should not invent identity from weak
activity. Activity is not identity.

## What This Repo Owns

- App registration metadata.
- API key hashing, verification, and revocation.
- User consent and connection ids.
- Scope and category policy.
- Memory suggestion checks.
- Allowed memory summary checks.
- App credit events.
- Audit and usage records.

## What This Repo Does Not Own

- User-facing Wiki/Yourself screens.
- Context category algorithms.
- Durable memory ranking.
- Full user Wiki access for apps.
- Archived Intent, Capture, Inference, or Playground product paths.

## Routes

```text
GET  /health
GET  /v1/policy
POST /v1/access/verify
POST /v1/memory/suggestions
POST /v1/memory/proposals
POST /v1/wiki/proposals
GET  /v1/memory
GET  /v1/context
GET  /v1/credits
POST /v1/cap/requests
GET  /v1/cap/requests/:id
POST /v1/cap/packets
POST /v1/cap/proposals
```

Compatibility routes still exist for older integrations:

```text
POST /v1/capture/events
GET  /v1/features
POST /v1/features/:featureId/run
GET  /v1/schemas
```

`POST /v1/intent/predict` is no longer a core route and returns `410`.

## Memory Suggestions

Apps can suggest memory after consent:

```http
POST /v1/memory/suggestions
Authorization: Bearer mka_your_private_key
Content-Type: application/json
```

```json
{
  "connection_id": "connection_id_from_consent",
  "proposal": {
    "category": "fitness",
    "title": "Prefers strength workouts",
    "context": {
      "preference": "strength workouts"
    },
    "evidence": {
      "reason": "The user completed strength plans in this app."
    }
  }
}
```

Access verifies the key, connection, scopes, and category before creating a
pending Wiki proposal. The user still decides whether it becomes accepted
memory.

## CAP

CAP is the Context Access Protocol. It is how apps request specific approved
memory without browsing a user's whole Yourself page.

Example:

```json
{
  "connection_id": "connection_id_from_consent",
  "purpose": "onboarding_prefill",
  "requested_categories": ["fitness"],
  "requested_context": [
    { "description": "workout goal", "field_hint": "fitness.goal", "required": true },
    { "description": "dietary preference", "field_hint": "diet.preference", "required": false }
  ]
}
```

The response packet has `allowed_context` and `missing_context`. Missing fields
mean the app should ask the user normally. CAP never returns full profiles, raw
activity events, or unapproved memory.

See [`docs/cap.md`](./docs/cap.md).

## Credits

Credits are simple developer-side accounting.

- Specific app activity earns a smaller credit bonus because Memact still has
  to shape it before the user reviews it.
- A clear memory suggestion with evidence earns more.
- Reading allowed memory spends credits.

Users mainly see the human product: what apps know, what apps suggest, and what
they can change.

## Backend Reality Check

The backend is real in these places:

- API keys are hashed and checked.
- Consent and `connection_id` are checked before app access.
- Scopes and categories are enforced.
- Apps can create pending memory suggestions.
- Sensitive fields are stripped before storage.
- Allowed memory summaries require read scopes.
- CAP packets return only approved field fragments and missing fields.
- Credit events are recorded.
- The old intent route is not silently used as core API.

The backend is intentionally not pretending in these places:

- Apps do not get the full user Wiki.
- Context and Memory stay separate repos instead of being copied into Access.
- Older feature routes stay compatibility-only until a new product path replaces them.

## Development

```powershell
npm install
npm run check
```

## License

See `LICENSE`.
