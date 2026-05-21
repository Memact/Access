import test from "node:test"
import assert from "node:assert/strict"
import { createAccessServer } from "../src/server.mjs"
import { AccessService } from "../src/service.mjs"
import { MemoryStore } from "../src/store.mjs"

test("HTTP intent route is deprecated outside the core API", async () => {
  const service = new AccessService(new MemoryStore())
  const { origin, close } = await listen(createAccessServer(service))
  try {
    const response = await fetch(`${origin}/v1/intent/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({})
    })
    const payload = await response.json()
    assert.equal(response.status, 410)
    assert.equal(payload.error.code, "intent_core_removed")
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
