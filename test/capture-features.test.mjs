import test from "node:test"
import assert from "node:assert/strict"
import path from "node:path"
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
  assert.equal(listed.features.some((feature) => feature.feature_id === "adaptive-article-overview"), true)

  await assert.rejects(
    () => service.runFeature(key.key, "user-context-wiki", {
      connection_id: consent.consent.id,
      activity_categories: ["web:research"]
    }),
    /required scopes/
  )
})

test("adaptive article overview runs through Studio runtime", async () => {
  const { service, key, consent } = await setupAccess(["feature:run", "memory:read_summary", "schema:read"], {
    studioPath: path.resolve(process.cwd(), "..", "Studio"),
    categories: ["reading"]
  })
  const result = await service.runFeature(key.key, "adaptive-article-overview", {
    connection_id: consent.consent.id,
    activity_categories: ["reading"],
    input: {
      article: {
        title: "New AI policy rules",
        excerpt: "A regulator published new rules for AI systems.",
        topic: "ai policy",
        source: "Example News",
        estimated_read_time_minutes: 8
      },
      reading_memory: {
        average_read_time_seconds: 260,
        average_scroll_depth: 88,
        finish_rate: 0.82,
        preferred_topics: ["ai policy"],
        skipped_topics: ["celebrity"],
        preferred_article_length: "long",
        preferred_summary_style: "deep_dive",
        repeat_topics: ["ai policy"]
      },
      recent_events: []
    }
  })
  assert.equal(result.status, "ok")
  assert.equal(result.output.summary_style, "deep_dive")
  assert.ok(result.output.overview)
  assert.ok(Array.isArray(result.output.signals_used))
})

test("schema helper routes store schema and subschemas", async () => {
  const { service, key, consent } = await setupAccess(["schema:write", "schema:read"], { categories: ["reading"] })
  const created = await service.createSchemaDefinition(key.key, {
    connection_id: consent.consent.id,
    schema_id: "reading_preferences",
    category: "reading",
    description: "Reading behavior and article preference memory"
  })
  assert.equal(created.schema.schema_id, "reading_preferences")
  const sub = await service.addSubSchemaDefinition(key.key, "reading_preferences", {
    connection_id: consent.consent.id,
    sub_schema_id: "summary_style_preference",
    description: "Whether the user prefers quick briefs, key points, deep dives, or simple explainers"
  })
  assert.equal(sub.subschema.sub_schema_id, "summary_style_preference")
  const found = await service.getSchemaDefinition(key.key, "reading_preferences", {
    connection_id: consent.consent.id,
    activity_categories: ["reading"]
  })
  assert.equal(found.schema.subschemas.length, 1)
})

test("feature run uses Studio runtime when available", async () => {
  const { service, key, consent } = await setupAccess(["feature:run", "memory:read_summary"], {
    studioPath: path.resolve(process.cwd(), "..", "studio")
  })
  const result = await service.runFeature(key.key, "user-context-wiki", {
    connection_id: consent.consent.id,
    activity_categories: ["web:research"],
    input: {
      schema_packets: [
        {
          category: "research",
          schema_type: "learning",
          title: "API setup"
        }
      ]
    }
  })

  assert.equal(result.status, "ok")
  assert.equal(result.output.sections[0].id, "research:learning")
  const data = await service.store.read()
  assert.equal(data.feature_runs[0].status, "ok")
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

async function setupAccess(scopes, options = {}) {
  const service = new AccessService(new MemoryStore(), () => new Date(), options)
  const developer = await service.signup({ email: `dev-${Math.random()}@example.com`, password: "long password" })
  const user = await service.signup({ email: `user-${Math.random()}@example.com`, password: "long password" })
  const categories = options.categories || ["web:research"]
  const app = await service.registerApp(developer.user.id, {
    name: "Research App",
    categories
  })
  const key = await service.createApiKey(developer.user.id, {
    app_id: app.app.id,
    scopes
  })
  const consent = await service.connectApp(user.user.id, {
    app_id: app.app.id,
    scopes,
    categories
  })
  return { service, developer, user, app, key, consent }
}
