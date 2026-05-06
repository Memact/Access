import http from "node:http"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { loadLocalEnv } from "./env.mjs"
import { JsonFileStore } from "./store.mjs"
import { AccessError, AccessService } from "./service.mjs"
import { SENSITIVE_CAPTURE_RULES } from "./policy.mjs"

loadLocalEnv()

const host = process.env.MEMACT_ACCESS_HOST || "127.0.0.1"
const port = Number(process.env.PORT || process.env.MEMACT_ACCESS_PORT || 8787)
const storePath = process.env.MEMACT_ACCESS_STORE || ".data/access-store.json"
const allowedOrigins = new Set(String(process.env.MEMACT_ACCESS_ALLOWED_ORIGINS || "http://localhost:3000,http://localhost:5173,http://localhost:4173,https://www.memact.com")
  .split(",")
  .map((item) => item.trim())
  .filter(Boolean))

export function createAccessServer(service) {
  return http.createServer(async (request, response) => {
    try {
      if (request.method === "OPTIONS") {
        send(response, 204, null, request)
        return
      }
      const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`)
      const body = await readJson(request)
      const result = await route(service, request, url, body)
      send(response, 200, result, request)
    } catch (error) {
      const status = error instanceof AccessError ? error.status : 500
      const message = status === 500
        ? safeInternalErrorMessage(error)
        : error.message
      send(response, status, {
        error: {
          code: error.code || "internal_error",
          message
        }
      }, request)
    }
  })
}

function safeInternalErrorMessage(error) {
  const raw = String(error?.message || "")
  if (/fetch failed|network|ENOTFOUND|ECONNREFUSED|ETIMEDOUT|supabase/i.test(raw)) {
    return "Access could not verify Supabase login. Check Access .env and network settings."
  }
  return "Access could not complete the request. Check Access logs."
}

async function route(service, request, url, body) {
  const path = url.pathname
  if (request.method === "GET" && path === "/health") {
    return { ok: true, service: "memact-access", version: "v0.0" }
  }
  if (request.method === "GET" && path === "/v1/policy") {
    return {
      ...(await service.policy()),
      sensitive_capture_rules: SENSITIVE_CAPTURE_RULES
    }
  }
  if (request.method === "POST" && path === "/v1/auth/signup") {
    return service.signup(body)
  }
  if (request.method === "POST" && path === "/v1/auth/signin") {
    return service.signin(body)
  }

  if (request.method === "POST" && path === "/v1/access/verify") {
    return service.verifyApiAccess(request.headers["x-memact-api-key"], body?.required_scopes || [])
  }

  const auth = await service.authenticateSession(request.headers.authorization)
  if (request.method === "GET" && path === "/v1/me") {
    return { user: auth.user }
  }
  if (request.method === "GET" && path === "/v1/apps") {
    return service.listApps(auth.user.id)
  }
  if (request.method === "POST" && path === "/v1/apps") {
    return service.registerApp(auth.user.id, body)
  }
  if (request.method === "GET" && path === "/v1/api-keys") {
    return service.listApiKeys(auth.user.id)
  }
  if (request.method === "POST" && path === "/v1/api-keys") {
    return service.createApiKey(auth.user.id, body)
  }
  if (request.method === "POST" && path === "/v1/api-keys/revoke") {
    return service.revokeApiKey(auth.user.id, body?.key_id)
  }
  if (request.method === "GET" && path === "/v1/consents") {
    return service.listConsents(auth.user.id)
  }
  if (request.method === "POST" && path === "/v1/consents") {
    return service.grantConsent(auth.user.id, body)
  }
  if (request.method === "POST" && path === "/v1/consents/revoke") {
    return service.revokeConsent(auth.user.id, body?.consent_id)
  }

  throw new AccessError(404, "not_found", "Endpoint not found.")
}

async function readJson(request) {
  if (request.method === "GET" || request.method === "HEAD") return {}
  const chunks = []
  for await (const chunk of request) {
    chunks.push(chunk)
    if (Buffer.concat(chunks).length > 1024 * 1024) {
      throw new AccessError(413, "payload_too_large", "Payload is too large.")
    }
  }
  const raw = Buffer.concat(chunks).toString("utf8").trim()
  if (!raw) return {}
  try {
    return JSON.parse(raw)
  } catch {
    throw new AccessError(400, "invalid_json", "Request body must be valid JSON.")
  }
}

function send(response, status, payload, request) {
  const origin = request?.headers?.origin
  if (origin && allowedOrigins.has(origin)) {
    response.setHeader("Access-Control-Allow-Origin", origin)
    response.setHeader("Vary", "Origin")
  }
  response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Memact-API-Key")
  response.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
  response.setHeader("X-Content-Type-Options", "nosniff")
  response.setHeader("Referrer-Policy", "no-referrer")
  response.setHeader("Cache-Control", "no-store")
  if (payload === null) {
    response.writeHead(status)
    response.end()
    return
  }
  response.setHeader("Content-Type", "application/json; charset=utf-8")
  response.writeHead(status)
  response.end(`${JSON.stringify(payload)}\n`)
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const service = new AccessService(new JsonFileStore(storePath))
  createAccessServer(service).listen(port, host, () => {
    console.log(`Memact Access listening on http://${host}:${port}`)
  })
}
