import test from "node:test"
import assert from "node:assert/strict"
import { createAccessServer } from "../src/server.mjs"
import { AccessService } from "../src/service.mjs"
import { MemoryStore } from "../src/store.mjs"

test("HTTP verification accepts a Bearer Memact API key", async () => {
  const service = new AccessService(new MemoryStore())
  const signup = await service.signup({ email: "server@example.com", password: "correct horse battery" })
  const app = await service.registerApp(signup.user.id, { name: "Server App", categories: ["web:research"] })
  const key = await service.createApiKey(signup.user.id, {
    app_id: app.app.id,
    scopes: ["memory:read_summary"]
  })
  await service.grantConsent(signup.user.id, {
    app_id: app.app.id,
    scopes: ["memory:read_summary"],
    categories: ["web:research"]
  })

  const { origin, close } = await listen(createAccessServer(service))
  try {
    const response = await fetch(`${origin}/v1/access/verify`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${key.key}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        required_scopes: ["memory:read_summary"],
        activity_categories: ["web:research"]
      })
    })

    assert.equal(response.status, 200)
    const payload = await response.json()
    assert.equal(payload.allowed, true)
    assert.equal(payload.app.name, "Server App")
  } finally {
    await close()
  }
})

test("HTTP verification can proxy to Supabase-backed Access records", async () => {
  const previousBackend = process.env.MEMACT_ACCESS_BACKEND
  const previousUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
  const previousKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
  const previousFetch = globalThis.fetch
  const requests = []

  process.env.MEMACT_ACCESS_BACKEND = "supabase"
  process.env.NEXT_PUBLIC_SUPABASE_URL = "https://example.supabase.co"
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = "public-anon-key"
  globalThis.fetch = async (url, options) => {
    requests.push({ url, options })
    return new Response(JSON.stringify({
      allowed: true,
      connection_id: "consent-1",
      scopes: ["memory:read_summary"],
      categories: ["web:research"]
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    })
  }

  const { origin, close } = await listen(createAccessServer({}))
  try {
    const response = await previousFetch(`${origin}/v1/access/verify`, {
      method: "POST",
      headers: {
        Authorization: "Bearer mka_private_key",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        connection_id: "consent-1",
        required_scopes: ["memory:read_summary"],
        activity_categories: ["web:research"]
      })
    })

    assert.equal(response.status, 200)
    assert.equal(requests.length, 1)
    assert.equal(requests[0].url, "https://example.supabase.co/rest/v1/rpc/memact_verify_api_key")
    assert.equal(requests[0].options.headers.Authorization, "Bearer public-anon-key")
    assert.deepEqual(JSON.parse(requests[0].options.body), {
      api_key_input: "mka_private_key",
      required_scopes_input: ["memory:read_summary"],
      activity_categories_input: ["web:research"],
      consent_id_input: "consent-1"
    })
  } finally {
    await close()
    globalThis.fetch = previousFetch
    restoreEnv("MEMACT_ACCESS_BACKEND", previousBackend)
    restoreEnv("NEXT_PUBLIC_SUPABASE_URL", previousUrl)
    restoreEnv("NEXT_PUBLIC_SUPABASE_ANON_KEY", previousKey)
  }
})

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject)
    server.listen(0, "127.0.0.1", () => {
      const address = server.address()
      resolve({
        origin: `http://127.0.0.1:${address.port}`,
        close: () => new Promise((closeResolve, closeReject) => {
          server.close((error) => error ? closeReject(error) : closeResolve())
        })
      })
    })
  })
}

function restoreEnv(key, value) {
  if (value === undefined) {
    delete process.env[key]
  } else {
    process.env[key] = value
  }
}
