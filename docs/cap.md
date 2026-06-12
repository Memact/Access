# Context Access Protocol

CAP means Context Access Protocol. It is internal backend naming, not user-facing
branding.

Users should see "Connect Memact." Developers can call CAP routes from their
server.

## What CAP Does

An app asks:

```text
What approved memory can this user share for this task?
```

Access checks the API key, connection, scopes, categories, and revocation. Memory
contributes only approved field records. Context matching maps the app's field
descriptions to possible memory fields. Access returns a small CAP packet.

CAP packets include:

- approved context fragments
- missing fields Memact could not safely answer
- fixed forbidden protections
- review status

CAP packets do not include:

- full profiles
- raw activity events
- unapproved memory
- unrelated categories
- sensitive fields unless explicitly allowed

## Routes

```text
POST /v1/cap/requests
GET  /v1/cap/requests/:id
POST /v1/cap/packets
POST /v1/cap/proposals
```

## App Flow

```text
App asks for specific context
-> Access checks permission
-> Memory retrieves approved fields only
-> Context matching picks candidate fields
-> CAP packet returns allowed and missing context
-> App asks the user normally for anything missing
```

Apps can also propose new context back to Memact. Those proposals start pending
and stay user-reviewable.

## AI Rule

Memact AI, if added later, must be memory-blind by default.

A model or worker should receive only the tiny CAP packet for the task. It should
not receive a full profile, raw events, or the whole memory store.

The current implementation works without LLMs or cloud APIs.
