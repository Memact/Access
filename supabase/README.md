# Memact Access on Supabase

Access now deploys best as a Supabase-backed permission layer instead of a paid
Node host.

Use the SQL migration in:

```text
supabase/migrations/20260507120000_memact_access.sql
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
- `memact_create_api_key`
- `memact_revoke_api_key`
- `memact_verify_api_key`

## Import Existing Local Access Data

If you already created apps or API keys with the old local JSON store, generate
an import SQL file:

```powershell
npm run seed:supabase
```

This writes:

```text
supabase/seed-from-local.sql
```

Run that SQL after the main migration. It maps old Access rows to Supabase
users by email.

## Why This Path

- avoids Render billing for the Access backend
- keeps auth and access data in one place
- gives durable storage instead of a local JSON file
- keeps API keys hashed
- keeps consent scoped per app
