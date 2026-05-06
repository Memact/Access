import test from "node:test"
import assert from "node:assert/strict"
import { AccessService } from "../src/service.mjs"
import { MemoryStore } from "../src/store.mjs"

test("signup hashes password and returns a session token", async () => {
  const service = new AccessService(new MemoryStore())
  const result = await service.signup({ email: "USER@example.com", password: "correct horse" })
  assert.equal(result.user.email, "user@example.com")
  assert.ok(result.session.token.startsWith("mss_"))
  const data = await service.store.read()
  assert.equal(data.users.length, 1)
  assert.notEqual(data.users[0].password_hash, "correct horse")
})

test("API keys are one-time raw secrets and stored as hashes", async () => {
  const service = new AccessService(new MemoryStore())
  const signup = await service.signup({ email: "builder@example.com", password: "long password" })
  const app = await service.registerApp(signup.user.id, { name: "Builder App" })
  const key = await service.createApiKey(signup.user.id, {
    app_id: app.app.id,
    scopes: ["capture:webpage", "schema:write", "graph:write"]
  })
  assert.ok(key.key.startsWith("mka_"))
  const data = await service.store.read()
  assert.equal(data.api_keys[0].key_hash.length, 64)
  assert.equal(data.api_keys[0].key_hash.includes(key.key), false)
})

test("API access requires both key scopes and user consent", async () => {
  const service = new AccessService(new MemoryStore())
  const signup = await service.signup({ email: "consent@example.com", password: "long password" })
  const app = await service.registerApp(signup.user.id, { name: "Capture App" })
  const key = await service.createApiKey(signup.user.id, {
    app_id: app.app.id,
    scopes: ["capture:webpage", "schema:write", "graph:write", "memory:read_summary"]
  })

  await assert.rejects(
    () => service.verifyApiAccess(key.key, ["capture:webpage"]),
    /User consent is required/
  )

  await service.grantConsent(signup.user.id, {
    app_id: app.app.id,
    scopes: ["capture:webpage", "schema:write", "graph:write"]
  })

  const allowed = await service.verifyApiAccess(key.key, ["capture:webpage", "graph:write"])
  assert.equal(allowed.allowed, true)
  assert.equal(allowed.policy.graph_read_allowed, false)

  await assert.rejects(
    () => service.verifyApiAccess(key.key, ["memory:read_summary"]),
    /required scopes/
  )
})

test("unknown scopes are rejected instead of silently accepted", async () => {
  const service = new AccessService(new MemoryStore())
  const signup = await service.signup({ email: "scope@example.com", password: "long password" })
  const app = await service.registerApp(signup.user.id, { name: "Scope App" })
  await assert.rejects(
    () => service.createApiKey(signup.user.id, { app_id: app.app.id, scopes: ["capture:everything"] }),
    /Unknown scopes/
  )
})

test("security emails are sent for signin, API key creation, and first API use", async () => {
  const messages = []
  const notifier = {
    async send(message) {
      messages.push(message)
      return { sent: true, channel: "test" }
    }
  }
  const service = new AccessService(new MemoryStore(), () => new Date("2026-05-06T00:00:00.000Z"), notifier)
  const signup = await service.signup({ email: "notify@example.com", password: "long password" })
  await service.signin({ email: "notify@example.com", password: "long password" })
  const app = await service.registerApp(signup.user.id, { name: "Notify App" })
  const key = await service.createApiKey(signup.user.id, {
    app_id: app.app.id,
    scopes: ["capture:webpage", "schema:write"]
  })
  await service.grantConsent(signup.user.id, {
    app_id: app.app.id,
    scopes: ["capture:webpage", "schema:write"]
  })
  await service.verifyApiAccess(key.key, ["capture:webpage"])
  await service.verifyApiAccess(key.key, ["capture:webpage"])

  assert.deepEqual(messages.map((message) => message.subject), [
    "New Memact sign-in",
    "Memact API key created",
    "Memact API usage started"
  ])
  assert.equal(messages.some((message) => message.text.includes(key.key)), false)
})
