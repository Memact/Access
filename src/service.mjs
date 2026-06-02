import { hashPassword, hashSecret, randomId, randomToken, verifyPassword } from "./crypto.mjs"
import fs from "node:fs"
import path from "node:path"
import {
  CATEGORY_DEFINITIONS,
  ACTIVITY_CATEGORY_REGISTRY,
  buildPermissionSuggestion,
  buildPresetSuggestions,
  buildUnderstandingStrategy,
  compilePolicy,
  CATEGORY_PERMISSION_MATRIX,
  DEFAULT_APP_CATEGORIES,
  DEFAULT_APP_SCOPES,
  hasAllCategories,
  hasAllScopes,
  KNOWLEDGE_GRAPH_CONTRACT,
  normalizeCategories,
  normalizeScopes,
  PERMISSION_REGISTRY,
  SAFETY_RULES,
  SCOPE_DEFINITIONS,
  unknownCategories,
  unknownScopes
} from "./policy.mjs"

const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 30

export class AccessError extends Error {
  constructor(status, code, message) {
    super(message)
    this.status = status
    this.code = code
  }
}

export class AccessService {
  constructor(store, now = () => new Date(), options = {}) {
    this.store = store
    this.now = now
    this.verifyExternalSession = options.verifyExternalSession || verifySupabaseAccessToken
    this.playgroundPath = options.playgroundPath || options.studioPath || process.env.MEMACT_PLAYGROUND_PATH || process.env.MEMACT_STUDIO_PATH || defaultPlaygroundPath()
  }

  async signup({ email, password, account_type = "developer" }) {
    const normalizedEmail = normalizeEmail(email)
    assertPassword(password)
    return this.mutate(async (data) => {
      if (data.users.some((user) => user.email === normalizedEmail)) {
        throw new AccessError(409, "email_exists", "An account already exists for this email.")
      }
      const user = {
        id: randomId("usr"),
        email: normalizedEmail,
        password_hash: await hashPassword(password),
        account_type: normalizeAccountType(account_type),
        account_state: "active",
        password_pending: false,
        created_from: "signup",
        full_signup_completed: true,
        plan: "free_unlimited",
        created_at: timestamp(this.now()),
        updated_at: timestamp(this.now())
      }
      data.users.push(user)
      audit(data, user.id, "user.signup", { email: normalizedEmail })
      const session = createSession(data, user.id, this.now)
      return { user: publicUser(user), session }
    })
  }

  async signin({ email, password }) {
    const normalizedEmail = normalizeEmail(email)
    return this.mutate(async (data) => {
      const user = data.users.find((item) => item.email === normalizedEmail)
      if (!user || !(await verifyPassword(password, user.password_hash))) {
        throw new AccessError(401, "invalid_credentials", "Email or password is incorrect.")
      }
      user.updated_at = timestamp(this.now())
      const session = createSession(data, user.id, this.now)
      audit(data, user.id, "user.signin", { email: normalizedEmail })
      return { user: publicUser(user), session }
    })
  }

  async authenticateSession(token) {
    const rawToken = extractBearer(token)
    if (!rawToken) {
      throw new AccessError(401, "invalid_session", "Session is missing or expired.")
    }
    const tokenHash = hashSecret(rawToken)
    const data = await this.store.read()
    const session = data.sessions.find((item) => item.token_hash === tokenHash && !item.revoked_at)
    if (session && new Date(session.expires_at).getTime() >= this.now().getTime()) {
      const user = data.users.find((item) => item.id === session.user_id)
      if (!user) {
        throw new AccessError(401, "invalid_session", "Session user no longer exists.")
      }
      return { user: publicUser(user), session: publicSession(session) }
    }

    const externalUser = await this.verifyExternalSession(rawToken)
    if (!externalUser?.id || !externalUser?.email) {
      throw new AccessError(401, "invalid_session", "Session is missing or expired.")
    }
    return this.mutate(async (nextData) => {
      const user = upsertExternalUser(nextData, externalUser, this.now)
      audit(nextData, user.id, "user.external_session", {
        provider: user.auth_provider || "supabase",
        email: user.email
      })
      return {
        user: publicUser(user),
        session: {
          id: `supabase:${externalUser.id}`,
          user_id: user.id,
          created_at: timestamp(this.now()),
          expires_at: null,
          revoked_at: null
        }
      }
    })
  }

  async registerApp(userId, { name, description = "", redirect_urls = [], developer_url = "", categories = DEFAULT_APP_CATEGORIES }) {
    const cleanName = String(name || "").trim()
    const slug = normalizeAppName(cleanName)
    const cleanCategories = assertCategories(categories)
    if (cleanName.length < 2) {
      throw new AccessError(400, "invalid_app_name", "App name must be at least 2 characters.")
    }
    if (!slug) {
      throw new AccessError(400, "invalid_app_name", "App name needs letters or numbers.")
    }
    return this.mutate(async (data) => {
      assertUser(data, userId)
      const duplicate = data.apps.some((app) => (
        app.owner_user_id === userId &&
        !app.revoked_at &&
        normalizeAppName(app.slug || app.name) === slug
      ))
      if (duplicate) {
        throw new AccessError(409, "duplicate_app_name", "You already have an app with this name.")
      }
      const app = {
        id: randomId("app"),
        owner_user_id: userId,
        name: cleanName.slice(0, 80),
        slug,
        description: String(description || "").trim().slice(0, 240),
        developer_url: normalizeOptionalUrl(developer_url),
        redirect_urls: Array.isArray(redirect_urls) ? redirect_urls.map(String).slice(0, 10) : [],
        default_scopes: [...DEFAULT_APP_SCOPES],
        default_categories: cleanCategories,
        compiled_policy: compilePolicy({
          appId: "",
          scopes: [],
          categories: cleanCategories,
          appPurpose: cleanName
        }),
        created_at: timestamp(this.now()),
        updated_at: timestamp(this.now()),
        revoked_at: null
      }
      app.compiled_policy = compilePolicy({
        appId: app.id,
        scopes: [],
        categories: cleanCategories,
        appPurpose: app.description || app.name
      })
      data.apps.push(app)
      audit(data, userId, "app.create", { app_id: app.id })
      return { app }
    })
  }

  async listApps(userId) {
    const data = await this.store.read()
    assertUser(data, userId)
    return {
      apps: data.apps.filter((app) => app.owner_user_id === userId && !app.revoked_at)
    }
  }

  async deleteApp(userId, appId) {
    return this.mutate(async (data) => {
      const app = data.apps.find((item) => item.id === appId && item.owner_user_id === userId && !item.revoked_at)
      if (!app) {
        throw new AccessError(404, "app_not_found", "App not found.")
      }
      const deletedAt = timestamp(this.now())
      app.revoked_at = deletedAt
      app.updated_at = deletedAt
      for (const key of data.api_keys) {
        if (key.app_id === app.id && key.owner_user_id === userId && !key.revoked_at) {
          key.revoked_at = deletedAt
        }
      }
      for (const consent of data.consents) {
        if (consent.app_id === app.id && consent.user_id === userId && !consent.revoked_at) {
          consent.revoked_at = deletedAt
          consent.updated_at = deletedAt
        }
      }
      audit(data, userId, "app.delete", { app_id: app.id })
      return { app: publicApp(app) }
    })
  }

  async createApiKey(userId, { app_id, name = "Default key", scopes = DEFAULT_APP_SCOPES }) {
    const unknown = unknownScopes(scopes)
    if (unknown.length) {
      throw new AccessError(400, "unknown_scope", `Unknown scopes: ${unknown.join(", ")}`)
    }
    const cleanScopes = normalizeScopes(scopes)
    if (!cleanScopes.length) {
      throw new AccessError(400, "missing_scopes", "At least one valid scope is required.")
    }
    return this.mutate(async (data) => {
      const app = data.apps.find((item) => item.id === app_id && item.owner_user_id === userId && !item.revoked_at)
      if (!app) {
        throw new AccessError(404, "app_not_found", "App not found.")
      }
      const rawKey = randomToken("mka", 36)
      const apiKey = {
        id: randomId("key"),
        app_id: app.id,
        owner_user_id: userId,
        name: String(name || "Default key").trim().slice(0, 80),
        key_hash: hashSecret(rawKey),
        key_prefix: rawKey.slice(0, 12),
        scopes: cleanScopes,
        created_at: timestamp(this.now()),
        last_used_at: null,
        revoked_at: null
      }
      data.api_keys.push(apiKey)
      audit(data, userId, "api_key.create", { app_id: app.id, key_id: apiKey.id, scopes: cleanScopes })
      return { api_key: publicApiKey(apiKey), key: rawKey }
    })
  }

  async listApiKeys(userId) {
    const data = await this.store.read()
    assertUser(data, userId)
    return {
      api_keys: data.api_keys
        .filter((key) => key.owner_user_id === userId)
        .map(publicApiKey)
    }
  }

  async revokeApiKey(userId, keyId) {
    return this.mutate(async (data) => {
      const key = data.api_keys.find((item) => item.id === keyId && item.owner_user_id === userId)
      if (!key) throw new AccessError(404, "api_key_not_found", "API key not found.")
      key.revoked_at = timestamp(this.now())
      audit(data, userId, "api_key.revoke", { key_id: key.id })
      return { api_key: publicApiKey(key) }
    })
  }

  async listFeatureConnections(userId) {
    const data = await this.store.read()
    assertUser(data, userId)
    return {
      feature_connections: data.feature_connections
        .filter((connection) => connection.owner_user_id === userId)
        .map(publicFeatureConnection)
    }
  }

  async connectFeature(userId, { feature_id, app_id, api_key_id } = {}) {
    const cleanFeatureId = String(feature_id || "").trim()
    if (!cleanFeatureId) throw new AccessError(400, "missing_feature_id", "Feature id is required.")
    return this.mutate(async (data) => {
      const feature = defaultFeatureRegistry().find((item) => item.feature_id === cleanFeatureId)
        || data.feature_registry.find((item) => item.feature_id === cleanFeatureId && item.enabled !== false)
      if (!feature) throw new AccessError(404, "feature_not_found", "Feature not found.")

      const app = data.apps.find((item) => item.id === app_id && item.owner_user_id === userId && !item.revoked_at)
      if (!app) throw new AccessError(404, "app_not_found", "App not found.")

      const activeKeys = data.api_keys
        .filter((key) => key.app_id === app.id && key.owner_user_id === userId && !key.revoked_at)
        .sort((first, second) => String(first.created_at).localeCompare(String(second.created_at)))
      const apiKey = api_key_id
        ? activeKeys.find((key) => key.id === api_key_id)
        : activeKeys[0]
      if (!apiKey) throw new AccessError(400, "api_key_required", "Create an API key before using this feature.")

      const existing = data.feature_connections.find((item) =>
        item.owner_user_id === userId
        && item.app_id === app.id
        && item.api_key_id === apiKey.id
        && item.feature_id === cleanFeatureId
        && !item.disconnected_at
      )
      if (existing) return { feature_connection: publicFeatureConnection(existing) }

      const connection = {
        id: randomId("fcn"),
        owner_user_id: userId,
        app_id: app.id,
        api_key_id: apiKey.id,
        feature_id: cleanFeatureId,
        created_at: timestamp(this.now()),
        disconnected_at: null
      }
      data.feature_connections.push(connection)
      audit(data, userId, "feature.connect", { app_id: app.id, api_key_id: apiKey.id, feature_id: cleanFeatureId })
      return { feature_connection: publicFeatureConnection(connection) }
    })
  }

  async disconnectFeature(userId, connectionId) {
    return this.mutate(async (data) => {
      const connection = data.feature_connections.find((item) => item.id === connectionId && item.owner_user_id === userId)
      if (!connection) throw new AccessError(404, "feature_connection_not_found", "Feature connection not found.")
      connection.disconnected_at = timestamp(this.now())
      audit(data, userId, "feature.disconnect", { connection_id: connection.id, feature_id: connection.feature_id })
      return { feature_connection: publicFeatureConnection(connection) }
    })
  }

  async grantConsent(userId, { app_id, scopes = DEFAULT_APP_SCOPES, categories = DEFAULT_APP_CATEGORIES }) {
    const unknown = unknownScopes(scopes)
    if (unknown.length) {
      throw new AccessError(400, "unknown_scope", `Unknown scopes: ${unknown.join(", ")}`)
    }
    const cleanCategories = assertCategories(categories)
    const cleanScopes = normalizeScopes(scopes)
    return this.mutate(async (data) => {
      const app = data.apps.find((item) => item.id === app_id && !item.revoked_at)
      if (!app) throw new AccessError(404, "app_not_found", "App not found.")
      const allowedCategories = normalizeCategories(app.default_categories || DEFAULT_APP_CATEGORIES)
      if (!hasAllCategories(allowedCategories, cleanCategories)) {
        throw new AccessError(400, "category_denied", "This app is not registered for one or more selected activity categories.")
      }
      const existing = data.consents.find((item) => item.user_id === userId && item.app_id === app.id && !item.revoked_at)
      if (existing) {
        existing.scopes = cleanScopes
        existing.categories = cleanCategories
        existing.compiled_policy = compilePolicy({
          appId: app.id,
          scopes: cleanScopes,
          categories: cleanCategories,
          appPurpose: app.description || app.name
        })
        existing.updated_at = timestamp(this.now())
        audit(data, userId, "consent.update", { app_id: app.id, scopes: cleanScopes, categories: cleanCategories })
        return { consent: existing }
      }
      const consent = {
        id: randomId("cns"),
        user_id: userId,
        app_id: app.id,
        scopes: cleanScopes,
        categories: cleanCategories,
        compiled_policy: compilePolicy({
          appId: app.id,
          scopes: cleanScopes,
          categories: cleanCategories,
          appPurpose: app.description || app.name
        }),
        created_at: timestamp(this.now()),
        updated_at: timestamp(this.now()),
        revoked_at: null
      }
      data.consents.push(consent)
      audit(data, userId, "consent.grant", { app_id: app.id, scopes: cleanScopes, categories: cleanCategories })
      return { consent }
    })
  }

  async listConsents(userId) {
    const data = await this.store.read()
    assertUser(data, userId)
    return {
      consents: data.consents.filter((item) => item.user_id === userId && !item.revoked_at)
    }
  }

  async revokeConsent(userId, consentId) {
    return this.mutate(async (data) => {
      const consent = data.consents.find((item) => item.id === consentId && item.user_id === userId)
      if (!consent) throw new AccessError(404, "consent_not_found", "Consent not found.")
      consent.revoked_at = timestamp(this.now())
      audit(data, userId, "consent.revoke", { consent_id: consent.id, app_id: consent.app_id })
      return { consent }
    })
  }

  async verifyApiAccess(apiKey, requiredScopes = [], requiredCategories = [], connectionId = "") {
    const cleanRequired = normalizeScopes(requiredScopes)
    const cleanRequiredCategories = normalizeCategories(requiredCategories)
    const keyHash = hashSecret(apiKey || "")
    return this.mutate(async (data) => {
      const key = data.api_keys.find((item) => item.key_hash === keyHash && !item.revoked_at)
      if (!key) {
        throw new AccessError(401, "invalid_api_key", "API key is invalid or revoked.")
      }
      const app = data.apps.find((item) => item.id === key.app_id && !item.revoked_at)
      if (!app) throw new AccessError(401, "app_revoked", "App is missing or revoked.")
      const consent = data.consents.find((item) => (
        item.app_id === key.app_id &&
        !item.revoked_at &&
        (connectionId ? item.id === connectionId : item.user_id === key.owner_user_id)
      ))
      if (!consent) {
        throw new AccessError(403, "consent_required", "User consent is required for this app.")
      }
      const effectiveScopes = intersectScopes(key.scopes, consent.scopes)
      const effectiveCategories = normalizeCategories(consent.categories || app.default_categories || DEFAULT_APP_CATEGORIES)
      const allowed = hasAllScopes(effectiveScopes, cleanRequired)
      const categoriesAllowed = hasAllCategories(effectiveCategories, cleanRequiredCategories)
      key.last_used_at = timestamp(this.now())
      audit(data, key.owner_user_id, allowed && categoriesAllowed ? "access.allow" : "access.deny", {
        app_id: app.id,
        required_scopes: cleanRequired,
        required_categories: cleanRequiredCategories,
        effective_scopes: effectiveScopes,
        effective_categories: effectiveCategories
      })
      if (!allowed) {
        throw new AccessError(403, "scope_denied", "API key or consent does not include the required scopes.")
      }
      if (!categoriesAllowed) {
        throw new AccessError(403, "category_denied", "App permission does not include the required activity categories.")
      }
      return {
        allowed: true,
        user_id: consent.user_id,
        connection_id: consent.id,
        app: publicApp(app),
        scopes: effectiveScopes,
        categories: effectiveCategories,
        compiled_policy: compilePolicy({
          appId: app.id,
          scopes: effectiveScopes,
          categories: effectiveCategories,
          appPurpose: app.description || app.name
        }),
        understanding_strategy: buildUnderstandingStrategy({
          scopes: effectiveScopes,
          categories: effectiveCategories
        }),
        policy: {
          plan: "free_unlimited",
          graph_read_allowed: effectiveScopes.includes("memory:read_graph")
        }
      }
    })
  }

  async ingestCaptureEvent(apiKey, body = {}, options = {}) {
    const category = String(body.category || body.activity_category || "").trim()
    if (!category) {
      throw new AccessError(400, "missing_category", "Capture event category is required.")
    }
    const eventType = String(body.event_type || body.type || "").trim()
    if (!eventType) {
      throw new AccessError(400, "missing_event_type", "Capture event type is required.")
    }
    const connectionId = body.connection_id || options.connectionId || ""
    const access = await this.verifyApiAccess(apiKey, ["capture:event_write"], [category], connectionId)
    return this.mutate(async (data) => {
      const event = {
        id: randomId("evt"),
        schema_version: body.schema_version || "memact.capture_event.v0",
        app_id: access.app.id,
        user_id: access.user_id,
        connection_id: access.connection_id,
        event_type: eventType.slice(0, 120),
        source_app: String(body.source_app || access.app.name || "app").slice(0, 120),
        category,
        payload: sanitizeCapturePayload(body.payload || {}),
        evidence: body.evidence && typeof body.evidence === "object" ? body.evidence : {},
        metadata: body.metadata && typeof body.metadata === "object" ? body.metadata : {},
        occurred_at: normalizeTimestamp(body.occurred_at) || timestamp(this.now()),
        created_at: timestamp(this.now())
      }
      data.capture_events.push(event)
      recordUsageEvent(data, "capture.event.accept", {
        app_id: access.app.id,
        connection_id: access.connection_id,
        category,
        event_id: event.id
      }, this.now)
      audit(data, access.user_id, "capture.event.accept", { app_id: access.app.id, event_id: event.id, category })
      return {
        accepted: true,
        event_id: event.id,
        app_id: event.app_id,
        connection_id: event.connection_id,
        category: event.category,
        created_at: event.created_at
      }
    })
  }

  async listCaptureEvents(userId, filter = {}) {
    const data = await this.store.read()
    assertUser(data, userId)
    const ownedAppIds = new Set(data.apps.filter((app) => app.owner_user_id === userId).map((app) => app.id))
    return {
      events: data.capture_events
        .filter((event) => ownedAppIds.has(event.app_id))
        .filter((event) => !filter.app_id || event.app_id === filter.app_id)
        .slice(-100)
        .map((event) => ({
          id: event.id,
          app_id: event.app_id,
          connection_id: event.connection_id,
          event_type: event.event_type,
          category: event.category,
          occurred_at: event.occurred_at,
          created_at: event.created_at
        }))
    }
  }

  async listFeatures() {
    const data = await this.store.read()
    const registry = data.feature_registry.length ? data.feature_registry : defaultFeatureRegistry()
    return { features: registry }
  }

  async verifyFeatureAccess(apiKey, featureId, body = {}) {
    const feature = defaultFeatureRegistry().find((item) => item.feature_id === featureId)
    if (!feature) {
      throw new AccessError(404, "feature_not_found", "Feature not found.")
    }
    const categories = Array.isArray(body.activity_categories) ? body.activity_categories : []
    const access = await this.verifyApiAccess(apiKey, feature.required_scopes || ["feature:run"], categories, body.connection_id || "")
    return { feature, access }
  }

  async runFeature(apiKey, featureId, body = {}) {
    const { feature, access } = await this.verifyFeatureAccess(apiKey, featureId, body)
    const runInput = body.input && typeof body.input === "object" ? body.input : body
    return this.mutate(async (data) => {
      const runtime = await runPlaygroundFeature(this.playgroundPath, feature.feature_id, runInput, {
        app: {
          id: access.app.id,
          name: access.app.name
        },
        connection_id: access.connection_id,
        categories: body.activity_categories || [],
        scopes: feature.required_scopes || []
      })
      const ok = runtime.status === "ok"
      const run = {
        id: randomId("frn"),
        feature_id: feature.feature_id,
        app_id: access.app.id,
        user_id: access.user_id,
        connection_id: access.connection_id,
        status: runtime.status,
        output: ok ? runtime.output : undefined,
        error: ok ? undefined : runtime.error,
        created_at: timestamp(this.now())
      }
      data.feature_runs.push(run)
      recordUsageEvent(data, ok ? "feature.run" : "feature.run.unavailable", { app_id: access.app.id, feature_id: feature.feature_id }, this.now)
      return ok ? runtime : { status: "error", error: run.error }
    })
  }

  async listSchemas(apiKey, options = {}) {
    const access = await this.verifyApiAccess(apiKey, ["schema:read"], options.activity_categories || [], options.connection_id || "")
    const data = await this.store.read()
    return {
      schema_definitions: data.schema_definitions
        .filter((schema) => !schema.app_id || schema.app_id === access.app.id)
        .map((schema) => ({
          ...schema,
          subschemas: data.subschema_definitions.filter((subschema) => subschema.schema_id === schema.schema_id && (!subschema.app_id || subschema.app_id === access.app.id))
        })),
      schemas: data.schema_packets
        .filter((packet) => !packet.app_id || packet.app_id === access.app.id)
        .map((packet) => ({
          packet_id: packet.packet_id || packet.id,
          category: packet.category,
          schema_type: packet.schema_type,
          confidence: packet.confidence,
          created_at: packet.created_at
        }))
    }
  }

  async createSchemaDefinition(apiKey, body = {}, options = {}) {
    const access = await this.verifyApiAccess(apiKey, ["schema:write"], body.category ? [body.category] : [], options.connectionId || body.connection_id || "")
    const schemaId = normalizeSchemaId(body.schema_id || body.id)
    if (!schemaId) throw new AccessError(400, "missing_schema_id", "Schema id is required.")
    const schema = {
      schema_id: schemaId,
      app_id: access.app.id,
      category: String(body.category || "general").trim().slice(0, 80),
      description: String(body.description || "").trim().slice(0, 500),
      created_at: timestamp(this.now()),
      updated_at: timestamp(this.now())
    }
    return this.mutate(async (data) => {
      data.schema_definitions = data.schema_definitions.filter((item) => !(item.app_id === access.app.id && item.schema_id === schema.schema_id))
      data.schema_definitions.push(schema)
      recordUsageEvent(data, "schema.definition.upsert", { app_id: access.app.id, schema_id: schema.schema_id }, this.now)
      return { schema }
    })
  }

  async addSubSchemaDefinition(apiKey, schemaId, body = {}, options = {}) {
    const access = await this.verifyApiAccess(apiKey, ["schema:write"], [], options.connectionId || body.connection_id || "")
    const cleanSchemaId = normalizeSchemaId(schemaId)
    const subSchemaId = normalizeSchemaId(body.sub_schema_id || body.subschema_id || body.id)
    if (!cleanSchemaId) throw new AccessError(400, "missing_schema_id", "Schema id is required.")
    if (!subSchemaId) throw new AccessError(400, "missing_subschema_id", "Subschema id is required.")
    const subSchema = {
      schema_id: cleanSchemaId,
      sub_schema_id: subSchemaId,
      app_id: access.app.id,
      description: String(body.description || "").trim().slice(0, 500),
      created_at: timestamp(this.now()),
      updated_at: timestamp(this.now())
    }
    return this.mutate(async (data) => {
      const schemaExists = data.schema_definitions.some((schema) => schema.app_id === access.app.id && schema.schema_id === cleanSchemaId)
      if (!schemaExists) throw new AccessError(404, "schema_not_found", "Schema definition not found.")
      data.subschema_definitions = data.subschema_definitions.filter((item) => !(item.app_id === access.app.id && item.schema_id === cleanSchemaId && item.sub_schema_id === subSchemaId))
      data.subschema_definitions.push(subSchema)
      recordUsageEvent(data, "schema.subschema.upsert", { app_id: access.app.id, schema_id: cleanSchemaId, sub_schema_id: subSchemaId }, this.now)
      return { subschema: subSchema }
    })
  }

  async getSchemaDefinition(apiKey, schemaId, options = {}) {
    const access = await this.verifyApiAccess(apiKey, ["schema:read"], options.activity_categories || [], options.connection_id || "")
    const cleanSchemaId = normalizeSchemaId(schemaId)
    const data = await this.store.read()
    const schema = data.schema_definitions.find((item) => item.schema_id === cleanSchemaId && (!item.app_id || item.app_id === access.app.id))
    if (!schema) throw new AccessError(404, "schema_not_found", "Schema definition not found.")
    return {
      schema: {
        ...schema,
        subschemas: data.subschema_definitions.filter((item) => item.schema_id === cleanSchemaId && (!item.app_id || item.app_id === access.app.id))
      }
    }
  }

  async listMemory(apiKey, options = {}) {
    const access = await this.verifyApiAccess(apiKey, ["memory:read_summary"], options.activity_categories || [], options.connection_id || "")
    const data = await this.store.read()
    return {
      memory: data.memory_records
        .filter((record) => !record.app_id || record.app_id === access.app.id)
        .map((record) => ({
          memory_id: record.memory_id || record.id,
          memory_type: record.memory_type || record.type,
          subject: record.subject || record.label,
          confidence: record.confidence,
          created_at: record.created_at
        }))
    }
  }

  async proposeWikiContext(apiKey, body = {}, options = {}) {
    const proposalInput = body.proposal && typeof body.proposal === "object" ? body.proposal : body
    const category = String(proposalInput.category || body.category || "").trim()
    const connectionId = body.connection_id || proposalInput.connection_id || options.connectionId || ""
    if (!category) throw new AccessError(400, "missing_category", "Wiki proposal category is required.")
    const access = await this.verifyApiAccess(apiKey, ["context:write"], [category], connectionId)
    const now = timestamp(this.now())
    const proposal = {
      entry_id: randomId("wkp"),
      schema_version: "memact.app_context_proposal.v0",
      app_id: access.app.id,
      connection_id: access.connection_id,
      user_id: access.user_id,
      source_app: String(proposalInput.source_app || access.app.name || "Connected app").trim().slice(0, 120),
      source_type: normalizeProposalSourceType(proposalInput.source_type),
      category,
      title: String(proposalInput.title || proposalInput.context?.title || `${category} context`).trim().slice(0, 160),
      context: sanitizeProposalContext(proposalInput.context || proposalInput.value || {}),
      value: sanitizeProposalContext(proposalInput.value || proposalInput.context || {}),
      status: "pending",
      visibility: "private",
      user_visible: proposalInput.user_visible !== false,
      confidence: normalizeConfidence(proposalInput.confidence),
      proposed_at: proposalInput.proposed_at || now,
      created_at: now,
      updated_at: now,
      source_trail: Array.isArray(proposalInput.source_trail) ? proposalInput.source_trail.slice(0, 20) : [],
      competing_interpretations: Array.isArray(proposalInput.competing_interpretations) ? proposalInput.competing_interpretations.slice(0, 10) : [],
      contradictions: Array.isArray(proposalInput.contradictions) ? proposalInput.contradictions.slice(0, 10) : []
    }
    return this.mutate(async (data) => {
      data.wiki_proposals.push(proposal)
      recordUsageEvent(data, "wiki.proposal.create", { app_id: access.app.id, category }, this.now)
      return { accepted: true, proposal }
    })
  }

  async recordUsage(action, details = {}) {
    return this.mutate(async (data) => {
      const event = recordUsageEvent(data, action, details, this.now)
      return { event }
    })
  }

  async getConnectApp(userId, { app_id, scopes = [], categories = [] }) {
    const cleanScopes = normalizeScopes(scopes)
    const cleanCategories = normalizeCategories(categories)
    const data = await this.store.read()
    assertUser(data, userId)
    const app = data.apps.find((item) => item.id === app_id && !item.revoked_at)
    if (!app) throw new AccessError(404, "app_not_found", "App not found.")
    return {
      app: publicApp(app),
      requested_scopes: cleanScopes.length ? cleanScopes : normalizeScopes(app.default_scopes || DEFAULT_APP_SCOPES),
      requested_categories: cleanCategories.length ? cleanCategories : normalizeCategories(app.default_categories || DEFAULT_APP_CATEGORIES),
      scopes: SCOPE_DEFINITIONS,
      activity_categories: CATEGORY_DEFINITIONS,
      permission_suggestion: buildPermissionSuggestion(cleanCategories.length ? cleanCategories : normalizeCategories(app.default_categories || DEFAULT_APP_CATEGORIES)),
      preset_suggestions: buildPresetSuggestions({
        categories: cleanCategories.length ? cleanCategories : normalizeCategories(app.default_categories || DEFAULT_APP_CATEGORIES),
        appPurpose: app.description || app.name
      }),
      safety_rules: SAFETY_RULES
    }
  }

  async connectApp(userId, { app_id, scopes = [], categories = [] }) {
    const appInfo = await this.getConnectApp(userId, { app_id, scopes, categories })
    const allowedCategories = normalizeCategories(appInfo.app.default_categories || DEFAULT_APP_CATEGORIES)
    if (!hasAllCategories(allowedCategories, appInfo.requested_categories)) {
      throw new AccessError(400, "category_denied", "This app is not registered for one or more requested categories.")
    }
    return this.grantConsent(userId, {
      app_id,
      scopes: appInfo.requested_scopes,
      categories: appInfo.requested_categories
    })
  }

  async policy() {
    return {
      plan: "free_unlimited",
      scopes: SCOPE_DEFINITIONS,
      permission_registry: PERMISSION_REGISTRY,
      default_app_scopes: DEFAULT_APP_SCOPES,
      activity_categories: CATEGORY_DEFINITIONS,
      activity_category_registry: ACTIVITY_CATEGORY_REGISTRY,
      category_permission_matrix: CATEGORY_PERMISSION_MATRIX,
      default_app_categories: DEFAULT_APP_CATEGORIES,
      permission_suggestion: buildPermissionSuggestion(DEFAULT_APP_CATEGORIES),
      preset_suggestions: buildPresetSuggestions({ categories: DEFAULT_APP_CATEGORIES }),
      permission_suggestions: Object.fromEntries(
        Object.keys(CATEGORY_DEFINITIONS).map((category) => [category, buildPermissionSuggestion([category])])
      ),
      safety_rules: SAFETY_RULES,
      knowledge_graph_contract: KNOWLEDGE_GRAPH_CONTRACT
    }
  }

  async mutate(fn) {
    const data = await this.store.read()
    const result = await fn(data)
    await this.store.write(data)
    return result
  }
}

function createSession(data, userId, now) {
  const rawToken = randomToken("mss", 36)
  const createdAt = timestamp(now())
  const session = {
    id: randomId("ses"),
    user_id: userId,
    token_hash: hashSecret(rawToken),
    created_at: createdAt,
    expires_at: new Date(now().getTime() + SESSION_TTL_MS).toISOString(),
    revoked_at: null
  }
  data.sessions.push(session)
  return { ...publicSession(session), token: rawToken }
}

function defaultPlaygroundPath() {
  const candidates = [
    path.resolve(process.cwd(), "..", "playground"),
    path.resolve(process.cwd(), "..", "Playground"),
    path.resolve(process.cwd(), "..", "studio")
  ]
  return candidates.find((candidate) => fs.existsSync(path.join(candidate, "src", "index.mjs"))) || candidates[0]
}

function defaultFeatureRegistry() {
  return [
    {
      feature_id: "adaptive-article-overview",
      name: "Adaptive Article Overview",
      description: "Creates article overviews based on the article and the user's approved reading memory.",
      required_scopes: ["feature:run", "memory:read_summary", "schema:read"],
      required_schema_types: ["reading_preferences"],
      service: "media"
    },
    {
      feature_id: "discord-channel-personalizer",
      name: "Discord Channel Personalizer",
      description: "Suggests Discord server channels from approved user memory and server channel context.",
      required_scopes: ["feature:run", "memory:read_summary", "schema:read", "platform:bot"],
      required_schema_types: ["community_preferences", "communication_preferences", "server_activity"],
      service: "community"
    },
    {
      feature_id: "community-context-brief",
      name: "Community Context Brief",
      description: "Summarizes approved community memory for apps and platform bots without exposing raw private activity.",
      required_scopes: ["feature:run", "memory:read_summary", "schema:read", "platform:bot"],
      required_schema_types: ["community_preferences", "platform_preferences", "communication_preferences"],
      service: "community"
    },
    {
      feature_id: "user-context-wiki",
      name: "Memory Wiki",
      description: "Groups permitted schema packets into readable sections with highlights and source trails.",
      required_scopes: ["feature:run", "memory:read_summary"],
      required_schema_types: ["*"]
    },
    {
      feature_id: "cognitive-load",
      name: "Cognitive Load",
      description: "Turns permitted activity and schema packets into a workload signal apps can adapt to.",
      required_scopes: ["feature:run", "schema:read"],
      required_schema_types: ["attention", "productivity", "work"]
    },
    {
      feature_id: "research-map",
      name: "Research Map",
      description: "Builds research themes, source trails, open questions, and next steps from permitted packets.",
      required_scopes: ["feature:run", "schema:read"],
      required_schema_types: ["research", "learning"]
    }
  ]
}

async function runPlaygroundFeature(playgroundPath, featureId, input, context) {
  try {
    const runtime = await import(pathToFileUrl(path.join(playgroundPath, "src", "index.mjs")))
    const feature = await runtime.loadFeature(path.join(playgroundPath, "features", featureId))
    return await runtime.runFeature(feature, input, context)
  } catch (error) {
    return {
      status: "error",
      error: {
        code: "feature_runtime_unavailable",
        message: "Feature runtime is not connected yet.",
        details: error instanceof Error ? error.message : String(error)
      }
    }
  }
}

function pathToFileUrl(filePath) {
  const normalized = path.resolve(filePath).replace(/\\/g, "/")
  return `file:///${normalized.replace(/^\/+/, "")}`
}

function sanitizeCapturePayload(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return {}
  const blocked = /password|token|secret|otp|card|cvv|authorization|cookie/i
  return Object.fromEntries(
    Object.entries(payload)
      .filter(([key]) => !blocked.test(key))
      .map(([key, value]) => [String(key).slice(0, 80), typeof value === "string" ? value.slice(0, 2000) : value])
  )
}

function normalizeTimestamp(value) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? "" : date.toISOString()
}

function normalizeSchemaId(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9:_-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 120)
}

function recordUsageEvent(data, action, details = {}, now) {
  const event = {
    id: randomId("use"),
    action,
    details,
    created_at: timestamp(now())
  }
  data.usage_events.push(event)
  if (data.usage_events.length > 5000) {
    data.usage_events.splice(0, data.usage_events.length - 5000)
  }
  return event
}

function audit(data, userId, action, details = {}) {
  data.audit_log.push({
    id: randomId("aud"),
    user_id: userId,
    action,
    details,
    created_at: new Date().toISOString()
  })
  if (data.audit_log.length > 2000) {
    data.audit_log.splice(0, data.audit_log.length - 2000)
  }
}

function normalizeEmail(email) {
  const value = String(email || "").trim().toLowerCase()
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value)) {
    throw new AccessError(400, "invalid_email", "A valid email is required.")
  }
  return value
}

function assertPassword(password) {
  if (String(password || "").length < 10) {
    throw new AccessError(400, "weak_password", "Password must be at least 10 characters.")
  }
}

function normalizeAppName(name) {
  return String(name || "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
}

function normalizeOptionalUrl(value) {
  const raw = String(value || "").trim()
  if (!raw) return ""
  try {
    const url = new URL(raw)
    if (!["https:", "http:"].includes(url.protocol)) return ""
    return url.toString()
  } catch {
    return ""
  }
}

function assertCategories(categories) {
  const unknown = unknownCategories(categories)
  if (unknown.length) {
    throw new AccessError(400, "unknown_category", `Unknown categories: ${unknown.join(", ")}`)
  }
  const cleanCategories = normalizeCategories(categories)
  if (!cleanCategories.length) {
    throw new AccessError(400, "missing_categories", "At least one activity category is required.")
  }
  return cleanCategories
}

function assertUser(data, userId) {
  const user = data.users.find((item) => item.id === userId)
  if (!user) throw new AccessError(404, "user_not_found", "User not found.")
  return user
}

async function verifySupabaseAccessToken(token) {
  const supabaseUrl = String(process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || "").replace(/\/+$/, "")
  const supabaseAnonKey = process.env.SUPABASE_ANON_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || ""
  if (!supabaseUrl || !supabaseAnonKey || !token) {
    return null
  }

  const response = await fetch(`${supabaseUrl}/auth/v1/user`, {
    headers: {
      apikey: supabaseAnonKey,
      Authorization: `Bearer ${token}`
    }
  }).catch(() => null)

  if (!response?.ok) {
    return null
  }

  const payload = await response.json().catch(() => null)
  if (!payload?.id || !payload?.email) {
    return null
  }
  return {
    id: `supabase:${payload.id}`,
    email: payload.email,
    auth_provider: payload.app_metadata?.provider || payload.identities?.[0]?.provider || "supabase",
    avatar_url: payload.user_metadata?.avatar_url || payload.user_metadata?.picture || "",
    account_type: payload.user_metadata?.account_type || payload.user_metadata?.memact_account_type || "",
    account_state: payload.user_metadata?.account_state || payload.user_metadata?.memact_account_state || "",
    password_pending: Boolean(payload.user_metadata?.password_pending),
    created_from: payload.user_metadata?.created_from || "",
    full_signup_completed: payload.user_metadata?.full_signup_completed
  }
}

function upsertExternalUser(data, externalUser, now) {
  let user = data.users.find((item) => item.external_auth_id === externalUser.id)
  if (!user) {
    user = data.users.find((item) => item.email === normalizeEmail(externalUser.email))
  }
  if (user) {
    user.external_auth_id = externalUser.id
    user.auth_provider = externalUser.auth_provider
    user.avatar_url = externalUser.avatar_url || user.avatar_url || ""
    if (externalUser.account_state === "consent_shell") {
      user.account_type = "user"
      user.account_state = "consent_shell"
      user.password_pending = true
      user.created_from = user.created_from || "consent_flow"
      user.full_signup_completed = false
    } else if (externalUser.account_type) {
      user.account_type = normalizeAccountType(externalUser.account_type)
    }
    user.updated_at = timestamp(now())
    return user
  }

  user = {
    id: randomId("usr"),
    external_auth_id: externalUser.id,
    email: normalizeEmail(externalUser.email),
    password_hash: null,
    auth_provider: externalUser.auth_provider || "supabase",
    avatar_url: externalUser.avatar_url || "",
    account_type: externalUser.account_state === "consent_shell" ? "user" : normalizeAccountType(externalUser.account_type),
    account_state: externalUser.account_state === "consent_shell" ? "consent_shell" : "active",
    password_pending: externalUser.account_state === "consent_shell" ? true : Boolean(externalUser.password_pending),
    created_from: externalUser.created_from || (externalUser.account_state === "consent_shell" ? "consent_flow" : "external_auth"),
    full_signup_completed: externalUser.account_state === "consent_shell" ? false : externalUser.full_signup_completed !== false,
    plan: "free_unlimited",
    created_at: timestamp(now()),
    updated_at: timestamp(now())
  }
  data.users.push(user)
  return user
}

function extractBearer(value) {
  const raw = String(value || "")
  return raw.toLowerCase().startsWith("bearer ") ? raw.slice(7).trim() : raw.trim()
}

function intersectScopes(first = [], second = []) {
  const secondSet = new Set(second)
  return normalizeScopes(first).filter((scope) => secondSet.has(scope))
}

function intersectCategories(first = [], second = []) {
  const secondSet = new Set(second)
  return normalizeCategories(first).filter((category) => secondSet.has(category))
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    provider: user.auth_provider || (user.external_auth_id ? "supabase" : "email"),
    avatar_url: user.avatar_url || "",
    account_type: user.account_type || (user.account_state === "consent_shell" ? "user" : "developer"),
    account_state: user.account_state || "active",
    password_pending: Boolean(user.password_pending),
    full_signup_completed: user.full_signup_completed !== false,
    plan: user.plan,
    created_at: user.created_at
  }
}

function normalizeAccountType(value) {
  return String(value || "").trim().toLowerCase() === "user" ? "user" : "developer"
}

function publicSession(session) {
  return {
    id: session.id,
    user_id: session.user_id,
    created_at: session.created_at,
    expires_at: session.expires_at,
    revoked_at: session.revoked_at
  }
}

function publicApp(app) {
  return {
    id: app.id,
    owner_user_id: app.owner_user_id,
    name: app.name,
    slug: app.slug || normalizeAppName(app.name),
    description: app.description,
    developer_url: app.developer_url || "",
    redirect_urls: app.redirect_urls || [],
    default_scopes: app.default_scopes,
    default_categories: app.default_categories || DEFAULT_APP_CATEGORIES,
    compiled_policy: app.compiled_policy || null,
    created_at: app.created_at,
    revoked_at: app.revoked_at
  }
}

function publicApiKey(apiKey) {
  return {
    id: apiKey.id,
    app_id: apiKey.app_id,
    owner_user_id: apiKey.owner_user_id,
    name: apiKey.name,
    key_prefix: apiKey.key_prefix,
    scopes: apiKey.scopes,
    created_at: apiKey.created_at,
    last_used_at: apiKey.last_used_at,
    revoked_at: apiKey.revoked_at
  }
}

function publicFeatureConnection(connection) {
  return {
    id: connection.id,
    owner_user_id: connection.owner_user_id,
    app_id: connection.app_id,
    api_key_id: connection.api_key_id,
    feature_id: connection.feature_id,
    created_at: connection.created_at,
    disconnected_at: connection.disconnected_at
  }
}

function normalizeProposalSourceType(value) {
  return ["app", "memact", "playground_feature", "user"].includes(value) ? value : "app"
}

function normalizeConfidence(value) {
  const number = Number(value)
  if (!Number.isFinite(number)) return null
  return Math.max(0, Math.min(1, number))
}

function sanitizeProposalContext(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {}
  return Object.fromEntries(
    Object.entries(value)
      .filter(([key]) => !/password|secret|token|api[_-]?key|credential/i.test(key))
      .map(([key, item]) => [String(key).slice(0, 80), sanitizeProposalValue(item)])
  )
}

function sanitizeProposalValue(value) {
  if (value === null || value === undefined) return value
  if (Array.isArray(value)) return value.slice(0, 50).map(sanitizeProposalValue)
  if (typeof value === "object") return sanitizeProposalContext(value)
  return String(value).slice(0, 1000)
}

function timestamp(date) {
  return date.toISOString()
}
