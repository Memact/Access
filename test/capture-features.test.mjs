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
  assert.equal(listed.features.some((feature) => feature.feature_id === "discord-channel-personalizer"), true)
  assert.equal(listed.features.some((feature) => feature.feature_id === "community-context-brief"), true)
  assert.equal(listed.features.find((feature) => feature.feature_id === "adaptive-article-overview").service, "media")

  await assert.rejects(
    () => service.runFeature(key.key, "user-context-wiki", {
      connection_id: consent.consent.id,
      activity_categories: ["web:research"]
    }),
    /required scopes/
  )
})

test("adaptive article overview runs through Playground runtime", async () => {
  const { service, key, consent } = await setupAccess(["feature:run", "memory:read_summary", "schema:read"], {
    playgroundPath: path.resolve(process.cwd(), "..", "playground"),
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

test("community platform features run through Playground runtime", async () => {
  const { service, key, consent } = await setupAccess(["feature:run", "memory:read_summary", "schema:read", "platform:bot"], {
    categories: ["community:discord"]
  })
  const discordResult = await service.runFeature(key.key, "discord-channel-personalizer", {
    connection_id: consent.consent.id,
    activity_categories: ["community:discord"],
    user_memory: {
      interests: ["memact", "developer tools"],
      muted_topics: ["memes"]
    },
    server: {
      channels: [
        { id: "1", name: "memact-api", topic: "developer tools and Memact help" },
        { id: "2", name: "memes", topic: "off-topic jokes" }
      ]
    }
  })
  assert.equal(discordResult.status, "ok")
  assert.equal(discordResult.output.recommended_channels[0].name, "memact-api")

  const briefResult = await service.runFeature(key.key, "community-context-brief", {
    connection_id: consent.consent.id,
    activity_categories: ["community:discord"],
    input: {
      platform: { platform: "discord" },
      approved_community_activity: [
        { channel: "memact-api", topics: ["api", "support"], summary: "User asks API support questions." }
      ],
      allowed_wiki_context: [
        { source: "Memact Wiki", interests: ["api"], communication_style: "concise updates" }
      ]
    }
  })
  assert.equal(briefResult.status, "ok")
  assert.ok(briefResult.output.topics_engaged_with.includes("api"))
})

test("features can connect to an app API key and disconnect later", async () => {
  const { service, developer, app, key } = await setupAccess(["feature:run", "memory:read_summary", "schema:read"], {
    categories: ["reading"]
  })

  const connected = await service.connectFeature(developer.user.id, {
    feature_id: "adaptive-article-overview",
    app_id: app.app.id,
    api_key_id: key.api_key.id
  })
  assert.equal(connected.feature_connection.feature_id, "adaptive-article-overview")
  assert.equal(connected.feature_connection.app_id, app.app.id)
  assert.equal(connected.feature_connection.api_key_id, key.api_key.id)

  const listed = await service.listFeatureConnections(developer.user.id)
  assert.equal(listed.feature_connections.length, 1)
  assert.equal(listed.feature_connections[0].disconnected_at, null)

  const disconnected = await service.disconnectFeature(developer.user.id, connected.feature_connection.id)
  assert.ok(disconnected.feature_connection.disconnected_at)
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

test("feature run uses Playground runtime when available", async () => {
  const { service, key, consent } = await setupAccess(["feature:run", "memory:read_summary"], {
    playgroundPath: path.resolve(process.cwd(), "..", "playground")
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

test("wiki proposals require context write and stay pending for user control", async () => {
  const { service, key, consent } = await setupAccess(["context:write"], { categories: ["preferences"] })
  const result = await service.proposeWikiContext(key.key, {
    connection_id: consent.consent.id,
    proposal: {
      source_app: "NutriPlan Lite",
      category: "preferences",
      title: "Fitness setup preferences",
      context: {
        fitness_goal: "maintenance",
        api_key: "should not persist"
      },
      confidence: 0.8
    }
  })

  assert.equal(result.accepted, true)
  assert.equal(result.proposal.status, "pending")
  assert.equal(result.proposal.visibility, "private")
  assert.equal(result.proposal.context.fitness_goal, "maintenance")
  assert.equal(Object.hasOwn(result.proposal.context, "api_key"), false)

  const data = await service.store.read()
  assert.equal(data.wiki_proposals.length, 1)
})

test("raw signals become pending context proposals with smaller credit bonus", async () => {
  const { service, key, consent, app } = await setupAccess(["context:write", "memory:read_summary"], { categories: ["fitness"] })
  const raw = await service.proposeWikiContext(key.key, {
    connection_id: consent.consent.id,
    raw_signal: {
      category: "fitness",
      event_type: "workout_completed",
      payload: {
        workout_type: "strength",
        password: "should not persist"
      }
    }
  })

  assert.equal(raw.accepted, true)
  assert.equal(raw.proposal.input_kind, "raw_signal")
  assert.equal(raw.proposal.status, "pending")
  assert.equal(raw.proposal.confidence, 0.35)
  assert.equal(raw.proposal.context.review_note.includes("Activity is not identity"), true)
  assert.equal(Object.hasOwn(raw.proposal.context.evidence, "password"), false)
  assert.equal(raw.credit_event.amount, 1)

  const direct = await service.proposeWikiContext(key.key, {
    connection_id: consent.consent.id,
    proposal: {
      category: "fitness",
      title: "Prefers strength workouts",
      context: { preference: "strength workouts" },
      source_trail: [{ type: "app_evidence", evidence: ["4 accepted workout logs"] }]
    }
  })
  assert.equal(direct.credit_event.amount, 4)
  assert.equal(direct.credits.balance, 5)

  const memory = await service.listMemory(key.key, {
    connection_id: consent.consent.id,
    activity_categories: ["fitness"]
  })
  assert.equal(memory.credit_event.amount, -1)
  assert.equal(memory.credits.balance, 4)

  const credits = await service.listCredits(key.key)
  assert.equal(credits.app_id, app.app.id)
  assert.equal(credits.balance, 4)
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
