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

test("HTTP memory suggestion route creates a pending user-reviewable proposal", async () => {
  const service = new AccessService(new MemoryStore())
  const developer = await service.signup({ email: "memory-dev@example.com", password: "correct horse battery" })
  const user = await service.signup({ email: "memory-user@example.com", password: "correct horse battery" })
  const app = await service.registerApp(developer.user.id, { name: "Fitness App", categories: ["fitness"] })
  const key = await service.createApiKey(developer.user.id, {
    app_id: app.app.id,
    scopes: ["context:write"],
    categories: ["fitness"]
  })
  const consent = await service.grantConsent(user.user.id, {
    app_id: app.app.id,
    scopes: ["context:write"],
    categories: ["fitness"]
  })

  const { origin, close } = await listen(createAccessServer(service))
  try {
    const response = await fetch(`${origin}/v1/memory/suggestions`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${key.key}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        connection_id: consent.consent.id,
        proposal: {
          category: "fitness",
          title: "Prefers strength workouts",
          context: { preference: "strength workouts" },
          evidence: { reason: "completed strength plans" }
        }
      })
    })

    assert.equal(response.status, 200)
    const payload = await response.json()
    assert.equal(payload.accepted, true)
    assert.equal(payload.proposal.status, "pending")
    assert.equal(payload.proposal.visibility, "private")
    assert.equal(payload.proposal.category, "fitness")
  } finally {
    await close()
  }
})

test("HTTP CAP packet route returns approved context and missing fields", async () => {
  const service = new AccessService(new MemoryStore())
  const developer = await service.signup({ email: "cap-dev@example.com", password: "correct horse battery" })
  const user = await service.signup({ email: "cap-user@example.com", password: "correct horse battery" })
  const app = await service.registerApp(developer.user.id, { name: "Fitness App", categories: ["fitness"] })
  const key = await service.createApiKey(developer.user.id, {
    app_id: app.app.id,
    scopes: ["cap:read_packet"]
  })
  const consent = await service.grantConsent(user.user.id, {
    app_id: app.app.id,
    scopes: ["cap:read_packet"],
    categories: ["fitness"]
  })
  await service.mutate(async (data) => {
    data.memory_records.push({
      field_path: "fitness.goal",
      value: "maintenance",
      category: "fitness",
      status: "approved",
      sensitivity: "normal",
      user_id: user.user.id,
      connection_id: consent.consent.id,
      allowed_app_ids: [app.app.id]
    })
  })

  const { origin, close } = await listen(createAccessServer(service))
  try {
    const response = await fetch(`${origin}/v1/cap/packets`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${key.key}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        connection_id: consent.consent.id,
        cap_request: {
          request_id: "cap_req_http",
          purpose: "onboarding_prefill",
          requested_categories: ["fitness"],
          requested_context: [
            { description: "workout goal", field_hint: "fitness.goal", required: true },
            { description: "dietary preference", field_hint: "diet.preference", required: false }
          ]
        }
      })
    })

    assert.equal(response.status, 200)
    const payload = await response.json()
    assert.equal(payload.packet.allowed_context[0].field_path, "fitness.goal")
    assert.equal(payload.packet.missing_context[0].field_hint, "diet.preference")
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
