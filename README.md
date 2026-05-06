# Memact Access

Version: `v0.0`

Access is the permission layer for Memact.

It owns:

- user signup and signin
- password hashing
- session tokens
- app registration
- API key creation and revocation
- consent records
- scope checks
- audit logs

Access does not capture activity, create nodes, create edges, or read a user's
memory graph. It decides who is allowed to ask Memact to do work.

Website users sign in with Supabase. Access verifies those Supabase access
tokens with the public Supabase anon key, then maps the verified user to local
apps, permissions, and API keys.

## Why This Exists

Memact is becoming infrastructure. Apps should be able to plug into Memact, but
not by reading a user's private graph.

The intended contract is:

```text
app asks for permission
-> user consents to specific scopes
-> app receives an API key
-> Memact performs allowed capture/schema work
-> app receives only the permitted output
```

API keys are capability keys, not memory dump keys.

## Default Policy

Access starts with free unlimited usage for now. The important boundary is
permission, not billing.

Scopes are explicit:

- `capture:webpage`
- `capture:media`
- `capture:device`
- `schema:write`
- `graph:write`
- `memory:write`
- `memory:read_summary`
- `memory:read_evidence`
- `memory:read_graph`

Raw graph reads are intentionally separate from capture/schema write scopes.

## Run Locally

```powershell
npm install
npm run dev
```

Health check:

```powershell
curl http://127.0.0.1:8787/health
```

Run checks:

```powershell
npm run check
```

## Supabase Session Verification

Set these public Supabase values for Access too:

```text
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-public-anon-key
```

Do not set a service role key here. Access only needs the anon key to ask
Supabase whether a browser session token is valid.

## API Shape

Signup:

```http
POST /v1/auth/signup
```

Signin:

```http
POST /v1/auth/signin
```

Register app:

```http
POST /v1/apps
Authorization: Bearer <session_token>
```

App names are unique per user after normalizing spaces and punctuation.

Delete app:

```http
DELETE /v1/apps/<app_id>
Authorization: Bearer <session_token>
```

Deleting an app revokes its active API keys and saved permissions.

Create API key:

```http
POST /v1/api-keys
Authorization: Bearer <session_token>
```

Grant consent:

```http
POST /v1/consents
Authorization: Bearer <session_token>
```

Verify app access:

```http
POST /v1/access/verify
X-Memact-API-Key: <api_key>
```

## Security Notes

- Passwords are hashed with `scrypt`.
- API keys and session tokens are stored as hashes only.
- API keys are shown once.
- Consent is scoped by user and app.
- Sensitive capture exclusions still happen in Capture before graph formation.
- Access is not a raw-memory export service.

## Render

`render.yaml` defines a Node web service for Access.

Render's free web service filesystem is not a durable database. It is fine for
testing the portal, but production Access should move the store to a managed
database or persistent storage.

## License

See `LICENSE`.
