import test from "node:test"
import assert from "node:assert/strict"
import fs from "node:fs/promises"

const latestMigrationPath = new URL("../supabase/migrations/20260508103000_stabilize_access_rpcs.sql", import.meta.url)
const fullInstallPath = new URL("../supabase/memact_access_full_install.sql", import.meta.url)

test("latest Supabase SQL qualifies pgcrypto calls through the extensions schema", async () => {
  const migration = await fs.readFile(latestMigrationPath, "utf8")
  const fullInstall = await fs.readFile(fullInstallPath, "utf8")

  for (const sql of [migration, fullInstall]) {
    assert.match(sql, /extensions\.digest\(/)
    assert.match(sql, /extensions\.gen_random_uuid\(\)/)
    assert.match(sql, /alter extension pgcrypto set schema extensions/)
    assert.equal(sql.includes("extensions.gen_random_bytes("), false)
    assert.doesNotMatch(sql, /gen_random_bytes\(24\)/)
  }
})

test("Supabase SQL asks PostgREST to reload the RPC schema cache", async () => {
  const migration = await fs.readFile(latestMigrationPath, "utf8")
  const fullInstall = await fs.readFile(fullInstallPath, "utf8")

  assert.match(migration, /notify pgrst, 'reload schema';/)
  assert.match(fullInstall, /notify pgrst, 'reload schema';/)
})

test("activity categories are not stored on API keys", async () => {
  const migration = await fs.readFile(latestMigrationPath, "utf8")
  const fullInstall = await fs.readFile(fullInstallPath, "utf8")

  for (const sql of [migration, fullInstall]) {
    assert.match(sql, /alter table public\.memact_api_keys\s+drop column if exists categories;/)
    assert.doesNotMatch(sql, /insert into public\.memact_api_keys \([^)]*categories/i)
    assert.doesNotMatch(sql, /target_key\.categories|created_key\.categories|key\.categories/)
  }
})

test("Supabase SQL drops stale overloaded create app functions", async () => {
  const migration = await fs.readFile(latestMigrationPath, "utf8")
  const fullInstall = await fs.readFile(fullInstallPath, "utf8")

  for (const sql of [migration, fullInstall]) {
    assert.match(sql, /drop function if exists public\.memact_create_app\(text, text, text\[\]\);/)
    assert.match(sql, /drop function if exists public\.memact_create_app\(text, text, text\[\], text\);/)
    assert.match(sql, /drop function if exists public\.memact_create_app\(text, text, text\[\], text, text\[\]\);/)
    assert.match(sql, /drop function if exists public\.memact_create_app\(text\[\], text, text, text, text\[\]\);/)
  }
})
