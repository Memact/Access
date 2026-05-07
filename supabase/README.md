# Memact Access on Supabase

Access now deploys best as a Supabase-backed permission layer instead of a paid
Node host.

Use the full ordered SQL bundle in the Supabase SQL editor for a new install or an existing project repair/update:

```text
supabase/memact_access_full_install.sql
```

If you prefer migration-by-migration deployment, run these files in order:

```text
supabase/migrations/20260507120000_memact_access.sql
supabase/migrations/20260507171000_fix_api_key_entropy.sql
supabase/migrations/20260507190000_qualify_access_crypto.sql
supabase/migrations/20260507203000_connect_categories_guardrails.sql
```

That migration creates:

- `memact_apps`
- `memact_api_keys`
- `memact_consents`
- `memact_audit_log`
- policy and verification RPC functions

## Apply It

Use the Supabase SQL editor and run the migration file, or apply it through the
Supabase CLI if you already use it.

After the migration, the Website portal can call these RPC functions directly:

- `memact_policy`
- `memact_dashboard`
- `memact_create_app`
- `memact_delete_app`
- `memact_grant_consent`
- `memact_get_connect_app`
- `memact_connect_app`
- `memact_create_api_key`
- `memact_revoke_api_key`
- `memact_verify_api_key`

`memact_verify_api_key` now checks:

- API key hash
- app status
- user consent
- requested scopes
- requested activity categories
- optional `connection_id` from the Connect App flow

## Import Existing Local Access Data

If you already created apps or API keys with the old local JSON store, generate
an import SQL file:

```powershell
npm run seed:supabase
```

This writes:

```text
.data/supabase-seed-from-local.sql
```

Run that SQL after the main migration. The generated file can include local
account emails, so it is kept under `.data/` and must not be committed. It maps old Access rows to Supabase
users by email.

## Why This Path

- avoids Render billing for the Access backend
- keeps auth and access data in one place
- gives durable storage instead of a local JSON file
- keeps API keys hashed
- keeps consent scoped per app
- lets apps request only the activity categories they need
- supports a Discord-style user approval page before an app connects
