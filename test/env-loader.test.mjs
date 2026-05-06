import assert from "node:assert/strict"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import test from "node:test"
import { loadLocalEnv } from "../src/env.mjs"

test("local env loader reads missing values without overriding existing env", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "memact-env-"))
  const file = path.join(dir, ".env")
  const previous = process.env.MEMACT_ENV_TEST
  const previousKept = process.env.MEMACT_ENV_KEEP
  process.env.MEMACT_ENV_KEEP = "already-set"
  delete process.env.MEMACT_ENV_TEST

  fs.writeFileSync(file, "MEMACT_ENV_TEST=loaded\nMEMACT_ENV_KEEP=from-file\n", "utf8")
  loadLocalEnv(file)

  assert.equal(process.env.MEMACT_ENV_TEST, "loaded")
  assert.equal(process.env.MEMACT_ENV_KEEP, "already-set")

  if (previous === undefined) delete process.env.MEMACT_ENV_TEST
  else process.env.MEMACT_ENV_TEST = previous
  if (previousKept === undefined) delete process.env.MEMACT_ENV_KEEP
  else process.env.MEMACT_ENV_KEEP = previousKept
})
