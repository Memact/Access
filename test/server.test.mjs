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

test("HTTP intent prediction route is no longer core", async () => {
  const previousBackend = process.env.MEMACT_ACCESS_BACKEND
  const previousUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
  const previousKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
  const previousFetch = globalThis.fetch

  process.env.MEMACT_ACCESS_BACKEND = "supabase"
  process.env.NEXT_PUBLIC_SUPABASE_URL = "https://example.supabase.co"
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = "public-anon-key"
  globalThis.fetch = async () => new Response("{}", { status: 200 })

  const { origin, close } = await listen(createAccessServer({}))
  try {
    const response = await previousFetch(`${origin}/v1/intent/predict`, {
      method: "POST",
      headers: {
        Authorization: "Bearer mka_private_key",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        connection_id: "consent-1",
        required_scopes: ["memory:read_summary"],
        activity_categories: ["web:research", "web:social"],
        activities: [
          { id: "approved", type: "documentation_page", category: "web:research", label: "Read API documentation guide" },
          { id: "blocked", type: "social_post", category: "web:social", label: "Reply to public thread" }
        ]
      })
    })

    assert.equal(response.status, 410)
    const payload = await response.json()
    assert.equal(payload.error.code, "intent_core_removed")
  } finally {
    await close()
    globalThis.fetch = previousFetch
    restoreEnv("MEMACT_ACCESS_BACKEND", previousBackend)
    restoreEnv("NEXT_PUBLIC_SUPABASE_URL", previousUrl)
    restoreEnv("NEXT_PUBLIC_SUPABASE_ANON_KEY", previousKey)
  }
})

test("HTTP /v1/context/query route returns context matches", async () => {
  const service = new AccessService(new MemoryStore())
  const signup = await service.signup({ email: "server@example.com", password: "correct horse battery" })
  const app = await service.registerApp(signup.user.id, { name: "Server App", categories: ["fitness"] })
  const key = await service.createApiKey(signup.user.id, {
    app_id: app.app.id,
    scopes: ["memory:read_summary"]
  })
  const consent = await service.grantConsent(signup.user.id, {
    app_id: app.app.id,
    scopes: ["memory:read_summary"],
    categories: ["fitness"]
  })

  // Add some memory records to the store directly
  await service.mutate(async (data) => {
    data.memory_records.push({
      id: "mem_test",
      connection_id: consent.consent.id,
      memory_type: "fitness",
      field_path: "workout_pref",
      value: "loves running",
      confidence: 0.95,
      created_at: new Date().toISOString()
    })
  })

  const { origin, close } = await listen(createAccessServer(service))
  try {
    const response = await fetch(`${origin}/v1/context/query`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${key.key}`,
        "Content-Type": "application/json",
        "x-memact-connection-id": consent.consent.id
      },
      body: JSON.stringify({
        requested_context: ["workout_pref"]
      })
    })

    assert.equal(response.status, 200)
    const payload = await response.json()
    assert.strictEqual(payload.requested_count, 1)
    assert.strictEqual(payload.memory_count, 1)
    assert.ok(Array.isArray(payload.matches))
    assert.strictEqual(payload.matches[0].candidates[0].memory.value, "loves running")
  } finally {
    await close()
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
