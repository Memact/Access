# Memact Permission Layer

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

Access does not infer intent, create nodes, create edges, or read a user's
memory graph. It decides who is allowed to ask Memact for understanding.

Website users sign in with Supabase. Access now works best as a Supabase-backed
permission layer too, so auth, apps, permissions, and API keys can live in the
same durable backend.

## Why This Exists

Memact is becoming permissioned context infrastructure. Apps should be able to
understand what a user is doing or trying to do, but not by reading a user's
private graph or treating captured activity as a raw data feed.

The intended contract is:

```text
app asks for permission
-> user consents to specific scopes
-> app receives an API key
-> Memact uses approved evidence, schemas, and memory
-> app receives only the permitted understanding
```

API keys are capability keys, not capture-export keys. A key identifies the app.
A user-specific `connection_id` identifies the user who approved that app.

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

Raw graph reads are intentionally separate from evidence, schema, and summary
scopes. The default product result is useful context, not raw captured data.

Activity categories are explicit too:

- `web:news`
- `web:research`
- `web:commerce`
- `web:social`
- `media:video`
- `media:audio`
- `ai:assistant`
- `dev:code`
- `work:docs`

This lets an app ask Memact to understand only the relevant part of a user's
activity. For example, a news-bias tool can request only `web:news`, while an
AI-conversation tool can request only `ai:assistant`.

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

For the easiest Website setup, run the full ordered SQL bundle in the Supabase SQL editor:

```text
supabase/memact_access_full_install.sql
```

That file combines the base install, API-key entropy repair, crypto qualification repair, and Connect/category guardrails in the correct order. If you prefer migration-by-migration deployment, run these files in order:

```text
supabase/migrations/20260507120000_memact_access.sql
supabase/migrations/20260507171000_fix_api_key_entropy.sql
supabase/migrations/20260507190000_qualify_access_crypto.sql
supabase/migrations/20260507203000_connect_categories_guardrails.sql
supabase/migrations/20260508103000_stabilize_access_rpcs.sql
supabase/migrations/20260515103000_understanding_strategy.sql
```

Then point Website at your Supabase project only.

The Supabase-backed permission layer creates:

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
- `memact_get_connect_app(...)`
- `memact_connect_app(...)`
- `memact_create_api_key(...)`
- `memact_revoke_api_key(...)`
- `memact_verify_api_key(...)`

These run as Supabase RPC functions after the SQL migration is applied.

Legacy local HTTP surface still exists for local fallback:

- `POST /v1/apps`
- `DELETE /v1/apps/<app_id>`
- `POST /v1/api-keys`
- `POST /v1/consents`
- `GET /v1/connect/app`
- `POST /v1/connect/approve`
- `POST /v1/access/verify`

## Developer Verification API

Apps should verify Memact access through the stable HTTP contract, not by
calling Supabase RPCs directly.

```http
POST /v1/access/verify
Authorization: Bearer mka_your_private_app_key
Content-Type: application/json
```

```json
{
  "connection_id": "connection_id_from_connect_redirect",
  "required_scopes": ["memory:read_summary"],
  "activity_categories": ["web:research"]
}
```

The response is the allowed app, user connection, approved scopes, approved
categories, policy context, and an `understanding_strategy`. If the key,
connection, scope, or category is missing, the endpoint returns an error and the
app must not request Memact context.

`understanding_strategy` is the important product contract. It is generated from
the effective API-key scopes, user consent, and activity categories. A news
article app gets a news/article strategy with article evidence, claims, sources,
reading intent, schema packets, and memory outputs. A coding app gets a developer
workflow strategy. A mixed category request gets a mixed strategy. Apps should
follow this object instead of treating Memact as a generic capture export.

Example response shape:

```json
{
  "allowed": true,
  "scopes": ["capture:webpage", "schema:write", "memory:read_summary"],
  "categories": ["web:news"],
  "understanding_strategy": {
    "product": "permissioned_understanding",
    "tagline": "Understand what users are trying to do.",
    "capture_plan": {
      "local_only_raw_capture": true,
      "allowed_inputs": ["article url", "headline", "selected article text"]
    },
    "understanding_plan": {
      "outputs": ["main claim", "supporting evidence", "reading intent"]
    },
    "delivery_plan": {
      "summaries": true,
      "evidence_cards": false,
      "graph_objects": false
    }
  }
}
```

For production, set:

```text
MEMACT_ACCESS_BACKEND=supabase
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-public-anon-key
```

The Supabase anon key is Memact infrastructure for this service. Third-party
app developers should not configure it in their apps; they only keep their raw
`mka_...` app key server-side.

App names stay unique per user after normalizing spaces and punctuation.
Deleting an app revokes its active API keys and saved permissions.

## Connect App Flow

Third-party apps should not silently attach themselves to a user. They should
send the user to Memact with:

```text
/connect?app_id=<app-id>&scopes=memory:read_summary&categories=web:news&redirect_uri=https://app.example/callback
```

Memact shows:

- app name
- developer website, if provided
- exact requested scopes in normal language
- exact activity categories
- a short boundary explaining what understanding the app can request

If the user approves, Access creates or updates a consent row and returns a
`connection_id` through the redirect URL. Future API checks should include both
the API key and that `connection_id`.

If the user cancels, no consent is created and API verification fails.

## Safety Guardrails

Access publishes policy guardrails that apps are expected to follow:

- no selling raw personal context
- no surveillance without user permission
- no manipulative targeting
- no political persuasion targeting
- no credit, employment, insurance, or housing decisions
- no sensitive trait inference unless the user explicitly asks for it

Capture is an evidence layer, not the product sold to apps. Sensitive source
exclusion still happens before graph formation or memory creation.

## Security Notes

- Passwords are hashed with `scrypt`.
- API keys and session tokens are stored as hashes only.
- API keys are shown once.
- Consent is scoped by user and app.
- Sensitive capture exclusions still happen before graph formation.
- Access is not a raw-memory or raw-capture export service.

## Render

`render.yaml` is now a legacy fallback for the old Node Access server.

The preferred production path is Supabase-backed Access, because it avoids
Render billing for a backend service and gives durable storage instead of a
local JSON file.

## License

See `LICENSE`.
