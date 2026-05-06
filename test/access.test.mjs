import test from "node:test"
import assert from "node:assert/strict"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { AccessService } from "../src/service.mjs"
import { JsonFileStore, MemoryStore } from "../src/store.mjs"

test("signup hashes password and returns a session token", async () => {
  const service = new AccessService(new MemoryStore())
  const result = await service.signup({ email: "USER@example.com", password: "correct horse" })
  assert.equal(result.user.email, "user@example.com")
  assert.ok(result.session.token.startsWith("mss_"))
  const data = await service.store.read()
  assert.equal(data.users.length, 1)
  assert.notEqual(data.users[0].password_hash, "correct horse")
})

test("signin works for a locally created account after restart", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "memact-access-"))
  const storePath = path.join(tempDir, "access.json")
  const password = "correct horse battery"
  try {
    const firstService = new AccessService(new JsonFileStore(storePath))
    await firstService.signup({ email: "local@example.com", password })

    const restartedService = new AccessService(new JsonFileStore(storePath))
    const result = await restartedService.signin({ email: "LOCAL@example.com", password })

    assert.equal(result.user.email, "local@example.com")
    assert.ok(result.session.token.startsWith("mss_"))
  } finally {
    await fs.rm(tempDir, { recursive: true, force: true })
  }
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
