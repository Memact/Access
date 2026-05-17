import test from "node:test"
import assert from "node:assert/strict"
import { createAccessServer } from "../src/server.mjs"
import { AccessService } from "../src/service.mjs"
import { MemoryStore } from "../src/store.mjs"
import { predictPermissionedIntent } from "../src/intent-service.mjs"
import { loadPredictIntent } from "../src/intent-engine.mjs"

test("Access can load the Intent engine from the local integration", async () => {
  const predictIntent = await loadPredictIntent()
  const result = predictIntent({ activities: researchActivities() }, { now: "2026-05-17T10:10:00.000Z" })

  assert.equal(typeof predictIntent, "function")
  assert.equal(result.schema_version, "memact.intent.v0")
})

test("intent prediction verifies key, connection, scope, and approved category", async () => {
  const { service, key, consent } = await setupIntentAccess()
  const result = await predictPermissionedIntent({
    service,
    apiKey: key.key,
    connectionId: consent.consent.id,
    requiredScopes: ["memory:read_summary"],
    activityCategories: ["web:research"],
    activities: researchActivities()
  })

  assert.equal(result.allowed, true)
  assert.equal(result.schema_version, "memact.intent.v0")
  assert.equal(result.intent.predicted_intents[0].id, "intent:research_learning")
  assert.ok(result.intent.predicted_intents[0].blocked_actions.length > 0)
  assert.equal(result.intent.safety.raw_capture_exposed, false)
})

test("intent prediction fails gracefully when the engine is unavailable", async () => {
  const { service, key, consent } = await setupIntentAccess()

  await assert.rejects(
    () => predictPermissionedIntent({
      service,
      apiKey: key.key,
      connectionId: consent.consent.id,
      activityCategories: ["web:research"],
      activities: researchActivities(),
      loadIntent: async () => {
        throw new Error("missing Intent engine")
      }
    }),
    /Intent prediction is temporarily unavailable/
  )
})

test("intent prediction fails without a valid API key", async () => {
  const { service, consent } = await setupIntentAccess()
  await assert.rejects(
    () => predictPermissionedIntent({
      service,
      apiKey: "mka_invalid",
      connectionId: consent.consent.id,
      activityCategories: ["web:research"],
      activities: researchActivities()
    }),
    /API key is invalid or revoked/
  )
})

test("intent prediction fails when consent is revoked", async () => {
  const { service, key, consent, user } = await setupIntentAccess()
  await service.revokeConsent(user.user.id, consent.consent.id)

  await assert.rejects(
    () => predictPermissionedIntent({
      service,
      apiKey: key.key,
      connectionId: consent.consent.id,
      activityCategories: ["web:research"],
      activities: researchActivities()
    }),
    /User consent is required/
  )
})

test("intent prediction excludes unapproved categories before calling Intent", async () => {
  const { service, key, consent } = await setupIntentAccess()
  const result = await predictPermissionedIntent({
    service,
    apiKey: key.key,
    connectionId: consent.consent.id,
    activityCategories: ["web:research", "web:social"],
    activities: [
      ...researchActivities(),
      {
        id: "social_1",
        type: "social_post",
        category: "web:social",
        label: "Share reply to a public thread",
        timestamp: "2026-05-17T10:03:00.000Z"
      }
    ]
  })

  assert.equal(result.filtered_activity_count, 2)
  assert.deepEqual(result.activity_categories, ["web:research"])
  assert.equal(result.intent.source.activity_count, 2)
  assert.equal(result.intent.predicted_intents.some((intent) => intent.id === "intent:content_sharing_or_reply"), false)
})

test("intent prediction returns low signal when no approved activity remains", async () => {
  const { service, key, consent } = await setupIntentAccess()
  const result = await predictPermissionedIntent({
    service,
    apiKey: key.key,
    connectionId: consent.consent.id,
    activityCategories: ["web:social"],
    activities: [{
      id: "social_1",
      type: "social_post",
      category: "web:social",
      label: "Share reply to a public thread"
    }]
  })

  assert.equal(result.filtered_activity_count, 0)
  assert.equal(result.intent.predicted_intents[0].id, "intent:low_signal")
})

test("sensitive approved activity does not influence intent prediction", async () => {
  const { service, key, consent } = await setupIntentAccess()
  const result = await predictPermissionedIntent({
    service,
    apiKey: key.key,
    connectionId: consent.consent.id,
    activityCategories: ["web:research"],
    activities: [{
      id: "sensitive_1",
      type: "documentation_page",
      category: "web:research",
      label: "Read medical diagnosis documentation guide",
      timestamp: "2026-05-17T10:00:00.000Z"
    }]
  })

  assert.equal(result.intent.predicted_intents[0].id, "intent:low_signal")
  assert.equal(result.intent.source.approved_activity_count, 0)
  assert.equal(result.intent.source.skipped_sensitive_activity_count, 1)
  assert.equal(result.intent.unresolved_signals[0].source_id, "sensitive_1")
})

test("intent response does not expose raw capture text", async () => {
  const { service, key, consent } = await setupIntentAccess()
  const result = await predictPermissionedIntent({
    service,
    apiKey: key.key,
    connectionId: consent.consent.id,
    activityCategories: ["web:research"],
    activities: [{
      id: "secret_notes",
      type: "documentation_page",
      category: "web:research",
      label: "Read API documentation guide",
      text: "private raw note that should not be returned",
      timestamp: "2026-05-17T10:00:00.000Z"
    }]
  })

  const raw = JSON.stringify(result)
  assert.equal(raw.includes("private raw note that should not be returned"), false)
  assert.ok(result.intent.predicted_intents[0].evidence[0].source_id)
})

test("intent:predict scope is required", async () => {
  const service = new AccessService(new MemoryStore())
  const developer = await service.signup({ email: "no-intent-dev@example.com", password: "long password" })
  const user = await service.signup({ email: "no-intent-user@example.com", password: "long password" })
  const app = await service.registerApp(developer.user.id, { name: "No Intent App", categories: ["web:research"] })
  const key = await service.createApiKey(developer.user.id, {
    app_id: app.app.id,
    scopes: ["memory:read_summary"]
  })
  const consent = await service.connectApp(user.user.id, {
    app_id: app.app.id,
    scopes: ["memory:read_summary"],
    categories: ["web:research"]
  })

  await assert.rejects(
    () => predictPermissionedIntent({
      service,
      apiKey: key.key,
      connectionId: consent.consent.id,
      activities: researchActivities()
    }),
    /required scopes/
  )
})

test("HTTP intent route returns safe envelope", async () => {
  const { service, key, consent } = await setupIntentAccess()
  const { origin, close } = await listen(createAccessServer(service))
  try {
    const response = await fetch(`${origin}/v1/intent/predict`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${key.key}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        connection_id: consent.consent.id,
        required_scopes: ["memory:read_summary"],
        activity_categories: ["web:research"],
        activities: researchActivities()
      })
    })
    const payload = await response.json()
    assert.equal(response.status, 200)
    assert.equal(payload.allowed, true)
    assert.equal(payload.schema_version, "memact.intent.v0")
    assert.ok(payload.intent.safety)
  } finally {
    await close()
  }
})

async function setupIntentAccess() {
  const service = new AccessService(new MemoryStore())
  const developer = await service.signup({ email: `dev-${Math.random()}@example.com`, password: "long password" })
  const user = await service.signup({ email: `user-${Math.random()}@example.com`, password: "long password" })
  const app = await service.registerApp(developer.user.id, {
    name: "Research App",
    categories: ["web:research"]
  })
  const key = await service.createApiKey(developer.user.id, {
    app_id: app.app.id,
    scopes: ["intent:predict", "memory:read_summary"]
  })
  const consent = await service.connectApp(user.user.id, {
    app_id: app.app.id,
    scopes: ["intent:predict", "memory:read_summary"],
    categories: ["web:research"]
  })
  return { service, developer, user, app, key, consent }
}

function researchActivities() {
  return [
    {
      id: "act_1",
      type: "documentation_page",
      category: "web:research",
      label: "Read API integration documentation guide",
      url: "https://example.com/docs",
      domain: "example.com",
      timestamp: "2026-05-17T10:00:00.000Z"
    },
    {
      id: "act_2",
      type: "tutorial",
      category: "web:research",
      label: "Open tutorial explaining integration reference",
      url: "https://example.com/tutorial",
      domain: "example.com",
      timestamp: "2026-05-17T10:04:00.000Z"
    }
  ]
}

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
