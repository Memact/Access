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
    capture_events: [],
    feature_runs: [],
    feature_connections: [],
    feature_registry: [],
    schema_definitions: [],
    subschema_definitions: [],
    wiki_proposals: [],
    schema_packets: [],
    memory_records: [],
    usage_events: [],
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
        slug: app.slug || normalizeAppName(app.name),
        compiled_policy: app.compiled_policy || null
      }))
      : [],
    api_keys: Array.isArray(base.api_keys)
      ? base.api_keys.map((key) => ({
        ...key,
        first_used_notified_at: key.first_used_notified_at || null
      }))
      : [],
    consents: Array.isArray(base.consents)
      ? base.consents.map((consent) => ({
        ...consent,
        compiled_policy: consent.compiled_policy || null
      }))
      : [],
    capture_events: Array.isArray(base.capture_events) ? base.capture_events : [],
    feature_runs: Array.isArray(base.feature_runs) ? base.feature_runs : [],
    feature_connections: Array.isArray(base.feature_connections) ? base.feature_connections : [],
    feature_registry: Array.isArray(base.feature_registry) ? base.feature_registry : [],
    schema_definitions: Array.isArray(base.schema_definitions) ? base.schema_definitions : [],
    subschema_definitions: Array.isArray(base.subschema_definitions) ? base.subschema_definitions : [],
    wiki_proposals: Array.isArray(base.wiki_proposals) ? base.wiki_proposals : [],
    schema_packets: Array.isArray(base.schema_packets) ? base.schema_packets : [],
    memory_records: Array.isArray(base.memory_records) ? base.memory_records : [],
    usage_events: Array.isArray(base.usage_events) ? base.usage_events : [],
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
