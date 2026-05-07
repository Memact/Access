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

Website users sign in with Supabase. Access now works best as a Supabase-backed
permission layer too, so auth, apps, permissions, and API keys can live in the
same durable backend.

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

The old local Node server still exists for local fallback and test coverage:

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

## Supabase-Backed Access

Production Access no longer needs a paid Node host.

Apply the SQL migration in:

```text
supabase/migrations/20260507120000_memact_access.sql
```

If the project already has the first migration, also apply the latest repair migration:

```text
supabase/migrations/20260507190000_qualify_access_crypto.sql
```

Then point Website at your Supabase project only.

The Supabase-backed Access layer creates:

- `memact_apps`
- `memact_api_keys`
- `memact_consents`
- `memact_audit_log`
- RPC functions for policy, dashboard, app creation, consent, key creation, and key verification

Helper notes live in:

[`supabase/README.md`](./supabase/README.md)

## Supabase Session Verification

Set these public Supabase values for Access too:

```text
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-public-anon-key
```

Do not set a service role key here. Access only needs the anon key to ask
Supabase whether a browser session token is valid.

## Import Existing Local Access Data

If you already created apps or keys with the old JSON store, generate a SQL
seed file:

```powershell
npm run seed:supabase
```

That writes:

```text
.data/supabase-seed-from-local.sql
```

Run it after the main Supabase migration. The generated file can include local
account emails, so it is kept under `.data/` and must not be committed. It maps old app/key/consent rows to
Supabase users by email.

## Access Surface

Primary production surface:

- `memact_policy()`
- `memact_dashboard()`
- `memact_create_app(...)`
- `memact_delete_app(...)`
- `memact_grant_consent(...)`
- `memact_create_api_key(...)`
- `memact_revoke_api_key(...)`
- `memact_verify_api_key(...)`

These run as Supabase RPC functions after the SQL migration is applied.

Legacy local HTTP surface still exists for local fallback:

- `POST /v1/apps`
- `DELETE /v1/apps/<app_id>`
- `POST /v1/api-keys`
- `POST /v1/consents`
- `POST /v1/access/verify`

App names stay unique per user after normalizing spaces and punctuation.
Deleting an app revokes its active API keys and saved permissions.

## Security Notes

- Passwords are hashed with `scrypt`.
- API keys and session tokens are stored as hashes only.
- API keys are shown once.
- Consent is scoped by user and app.
- Sensitive capture exclusions still happen in Capture before graph formation.
- Access is not a raw-memory export service.

## Render

`render.yaml` is now a legacy fallback for the old Node Access server.

The preferred production path is Supabase-backed Access, because it avoids
Render billing for a backend service and gives durable storage instead of a
local JSON file.

## License

See `LICENSE`.
