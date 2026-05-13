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
MEMACT_ACCESS_BACKEND=supabase
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

Then verify the developer API shape from a server or terminal:

```powershell
curl -X POST https://your-access-host/v1/access/verify `
  -H "Authorization: Bearer mka_your_private_app_key" `
  -H "Content-Type: application/json" `
  -d "{\"connection_id\":\"connection_id_from_connect_redirect\",\"required_scopes\":[\"memory:read_summary\"],\"activity_categories\":[\"web:research\"]}"
```

## Note

With `MEMACT_ACCESS_BACKEND=supabase`, verification uses the same Supabase-backed
Access records as the Website. Without that setting, the service falls back to
the old local JSON store for development only.
