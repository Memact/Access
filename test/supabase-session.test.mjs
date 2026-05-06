import assert from "node:assert/strict"
import test from "node:test"
import { AccessError, AccessService } from "../src/service.mjs"
import { MemoryStore } from "../src/store.mjs"

test("Access accepts a verified Supabase session token", async () => {
  const service = new AccessService(new MemoryStore(), () => new Date("2026-05-06T00:00:00.000Z"), {
    verifyExternalSession: async (token) => token === "sb_valid"
      ? {
          id: "supabase:user-1",
          email: "founder@memact.com",
          auth_provider: "github",
          avatar_url: "https://avatars.githubusercontent.com/u/1"
        }
      : null
  })

  const auth = await service.authenticateSession("Bearer sb_valid")
  assert.equal(auth.user.email, "founder@memact.com")
  assert.equal(auth.user.provider, "github")

  const appResult = await service.registerApp(auth.user.id, {
    name: "Research app",
    description: "Uses Memact memory"
  })
  const consentResult = await service.grantConsent(auth.user.id, {
    app_id: appResult.app.id,
    scopes: ["capture:webpage", "schema:write"]
  })

  assert.equal(consentResult.consent.app_id, appResult.app.id)
})

test("Access rejects unverified Supabase session tokens", async () => {
  const service = new AccessService(new MemoryStore(), () => new Date("2026-05-06T00:00:00.000Z"), {
    verifyExternalSession: async () => null
  })

  await assert.rejects(
    () => service.authenticateSession("Bearer sb_invalid"),
    (error) => error instanceof AccessError && error.code === "invalid_session"
  )
})
