import { hashPassword, hashSecret, randomId, randomToken, verifyPassword } from "./crypto.mjs"
import {
  CATEGORY_DEFINITIONS,
  DEFAULT_APP_CATEGORIES,
  DEFAULT_APP_SCOPES,
  hasAllCategories,
  hasAllScopes,
  KNOWLEDGE_GRAPH_CONTRACT,
  normalizeCategories,
  normalizeScopes,
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
  }

  async signup({ email, password }) {
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
        created_at: timestamp(this.now()),
        updated_at: timestamp(this.now()),
        revoked_at: null
      }
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
        policy: {
          plan: "free_unlimited",
          graph_read_allowed: effectiveScopes.includes("memory:read_graph")
        }
      }
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
      default_app_scopes: DEFAULT_APP_SCOPES,
      activity_categories: CATEGORY_DEFINITIONS,
      default_app_categories: DEFAULT_APP_CATEGORIES,
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
    avatar_url: payload.user_metadata?.avatar_url || payload.user_metadata?.picture || ""
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
    plan: user.plan,
    created_at: user.created_at
  }
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

function timestamp(date) {
  return date.toISOString()
}
