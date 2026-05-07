# Render Direct Deploy

Use this only if you deliberately want the old local-JSON Access server on a
host.

The recommended production path is now Supabase-backed Access instead of a paid
Node backend. See [`supabase/README.md`](./supabase/README.md).

## 1. Create The Service

In Render:

```text
New -> Web Service
Repository: https://github.com/Memact/Access
Branch: main
Name: memact-access
Runtime: Node
Build Command: npm ci
Start Command: npm start
Health Check Path: /health
```

Do not set `MEMACT_ACCESS_PORT`. Render provides `PORT` automatically.

## 2. Environment Variables

Add:

```text
NODE_ENV=production
MEMACT_ACCESS_HOST=0.0.0.0
MEMACT_ACCESS_STORE=.data/access-store.json
MEMACT_ACCESS_ALLOWED_ORIGINS=https://memact.com,https://www.memact.com,https://memact-website.onrender.com
NEXT_PUBLIC_SUPABASE_URL=<your Supabase project URL>
NEXT_PUBLIC_SUPABASE_ANON_KEY=<your Supabase anon key>
```

If Website gets a different Render URL, add it to `MEMACT_ACCESS_ALLOWED_ORIGINS`.

## 3. Verify

After deploy, open:

```text
https://memact-access.onrender.com/health
```

Expected:

```json
{"ok":true,"service":"memact-access","version":"v0.0"}
```

## Note

This demo service currently stores app records and API key hashes in a local JSON file. For production users, move this storage to Supabase/Postgres before relying on it as permanent infrastructure.
