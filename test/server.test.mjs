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

test("Audit Logging System traces context read requests (CAP requests)", async () => {
  const { auditLogger } = await import("../src/server.mjs")
  const logs = []
  const originalLog = auditLogger.log
  
  // Intercept the logger to capture log records
  auditLogger.log = (entry) => { logs.push(entry) }

  // Create a minimal mock service to bypass standard authentication or database requirements
  const mockService = {
    authenticateSession: async () => ({ user: { id: "user-123" }, token: "mock-token" }),
    requestContextPacket: async () => ({ ok: true })
  }

  const { origin, close } = await listen(createAccessServer(mockService))
  try {
    const response = await fetch(`${origin}/v1/cap/request`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer mock_user_session"
      },
      body: JSON.stringify({
        app_id: "client-app-xyz",
        category: "health_metrics",
        visibility_level: "private",
        raw_token: "SENSITIVE_TOKEN_THAT_SHOULD_NOT_BE_LOGGED" // Test privacy guard
      })
    })

    assert.equal(response.status, 200)
    assert.equal(logs.length, 1)
    
    const log = logs[0]
    assert.ok(log.timestamp, "Should contain a valid timestamp")
    assert.equal(log.app_id, "client-app-xyz")
    assert.equal(log.category, "health_metrics")
    assert.equal(log.visibility_level, "private")
    assert.equal(log.status, "allowed")
    
    // Privacy safeguard verification
    assert.equal(log.raw_token, undefined, "Privacy Guard Failure: leaked internal data tokens into audit log")
  } finally {
    await close()
    auditLogger.log = originalLog // Restore the original logger function
  }
})

test("Audit Logging System traces denied context access on route error", async () => {
  const { auditLogger } = await import("../src/server.mjs")
  const logs = []
  const originalLog = auditLogger.log
  
  auditLogger.log = (entry) => { logs.push(entry) }

  // Mock service that completely throws an error simulating a rejection or invalid key
  const mockService = {
    requestContextPacket: async () => {
      const { AccessError } = await import("../src/service.mjs")
      throw new AccessError(403, "access_denied", "Unauthorized category request.")
    }
  }

  const { origin, close } = await listen(createAccessServer(mockService))
  try {
    const response = await fetch(`${origin}/v1/cap/request`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        app_id: "untrusted-app",
        category: "financial_records",
        visibility_level: "restricted"
      })
    })

    assert.equal(response.status, 403)
    assert.equal(logs.length, 1)
    
    const log = logs[0]
    assert.equal(log.app_id, "untrusted-app")
    assert.equal(log.category, "financial_records")
    assert.equal(log.status, "denied")
  } finally {
    await close()
    auditLogger.log = originalLog
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
