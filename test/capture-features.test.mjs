import test from "node:test"
import assert from "node:assert/strict"
import { AccessService } from "../src/service.mjs"
import { MemoryStore } from "../src/store.mjs"

test("capture event accepts valid app signal after permission", async () => {
  const { service, key, consent } = await setupAccess(["capture:event_write", "memory:read_summary"])
  const result = await service.ingestCaptureEvent(key.key, {
    connection_id: consent.consent.id,
    event_type: "article_read",
    category: "web:research",
    payload: {
      title: "Integration guide",
      password: "should not persist"
    }
  })

  assert.equal(result.accepted, true)
  const data = await service.store.read()
  assert.equal(data.capture_events.length, 1)
  assert.equal(Object.hasOwn(data.capture_events[0].payload, "password"), false)
})

test("capture event rejects missing key and missing category", async () => {
  const { service } = await setupAccess(["capture:event_write"])
  await assert.rejects(
    () => service.ingestCaptureEvent("", { event_type: "article_read", category: "web:research" }),
    /API key is invalid or revoked/
  )
  await assert.rejects(
    () => service.ingestCaptureEvent("mka_fake", { event_type: "article_read" }),
    /category is required/
  )
})

test("feature registry is listed and feature run requires feature scope", async () => {
  const { service, key, consent } = await setupAccess(["memory:read_summary"])
  const listed = await service.listFeatures()
  assert.equal(listed.features.some((feature) => feature.feature_id === "user-context-wiki"), true)

  await assert.rejects(
    () => service.runFeature(key.key, "user-context-wiki", {
      connection_id: consent.consent.id,
      activity_categories: ["web:research"]
    }),
    /required scopes/
  )
})

test("schema and memory summary routes require their scopes", async () => {
  const { service, key, consent } = await setupAccess(["memory:read_summary"])
  await assert.rejects(
    () => service.listSchemas(key.key, { connection_id: consent.consent.id, activity_categories: ["web:research"] }),
    /required scopes/
  )

  const memory = await service.listMemory(key.key, { connection_id: consent.consent.id, activity_categories: ["web:research"] })
  assert.deepEqual(memory.memory, [])
})

async function setupAccess(scopes) {
  const service = new AccessService(new MemoryStore())
  const developer = await service.signup({ email: `dev-${Math.random()}@example.com`, password: "long password" })
  const user = await service.signup({ email: `user-${Math.random()}@example.com`, password: "long password" })
  const app = await service.registerApp(developer.user.id, {
    name: "Research App",
    categories: ["web:research"]
  })
  const key = await service.createApiKey(developer.user.id, {
    app_id: app.app.id,
    scopes
  })
  const consent = await service.connectApp(user.user.id, {
    app_id: app.app.id,
    scopes,
    categories: ["web:research"]
  })
  return { service, developer, user, app, key, consent }
}
