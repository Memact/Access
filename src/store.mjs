import fs from "node:fs"
import path from "node:path"

export function createEmptyStore() {
  return {
    schema_version: "memact.access.v0",
    users: [],
    sessions: [],
    apps: [],
    api_keys: [],
    consents: [],
    audit_log: []
  }
}

export class JsonFileStore {
  constructor(filePath) {
    this.filePath = filePath
  }

  async read() {
    if (!fs.existsSync(this.filePath)) {
      return createEmptyStore()
    }
    const raw = await fs.promises.readFile(this.filePath, "utf8")
    return migrateStore(JSON.parse(raw))
  }

  async write(data) {
    const next = migrateStore(data)
    await fs.promises.mkdir(path.dirname(this.filePath), { recursive: true })
    const tmpPath = `${this.filePath}.${process.pid}.tmp`
    await fs.promises.writeFile(tmpPath, `${JSON.stringify(next, null, 2)}\n`, "utf8")
    await fs.promises.rename(tmpPath, this.filePath)
    return next
  }
}

export class MemoryStore {
  constructor(seed = createEmptyStore()) {
    this.data = migrateStore(seed)
  }

  async read() {
    return migrateStore(JSON.parse(JSON.stringify(this.data)))
  }

  async write(data) {
    this.data = migrateStore(JSON.parse(JSON.stringify(data)))
    return this.read()
  }
}

export function migrateStore(data) {
  const base = data && typeof data === "object" ? data : {}
  return {
    schema_version: "memact.access.v0",
    users: Array.isArray(base.users)
      ? base.users.map((user) => ({
        ...user,
        external_auth_id: user.external_auth_id || null,
        auth_provider: user.auth_provider || null,
        avatar_url: user.avatar_url || ""
      }))
      : [],
    sessions: Array.isArray(base.sessions) ? base.sessions : [],
    apps: Array.isArray(base.apps)
      ? base.apps.map((app) => ({
        ...app,
        slug: app.slug || normalizeAppName(app.name)
      }))
      : [],
    api_keys: Array.isArray(base.api_keys)
      ? base.api_keys.map((key) => ({
        ...key,
        first_used_notified_at: key.first_used_notified_at || null
      }))
      : [],
    consents: Array.isArray(base.consents) ? base.consents : [],
    audit_log: Array.isArray(base.audit_log) ? base.audit_log : []
  }
}

function normalizeAppName(name) {
  return String(name || "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
}
