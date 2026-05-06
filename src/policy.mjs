export const SCOPE_DEFINITIONS = Object.freeze({
  "capture:webpage": {
    label: "Capture webpages",
    description: "Allow Memact to capture useful webpage content for this app.",
    grantsGraphRead: false
  },
  "capture:media": {
    label: "Capture media context",
    description: "Allow Memact to capture captions, transcripts, and media context when available.",
    grantsGraphRead: false
  },
  "capture:device": {
    label: "Capture device activity",
    description: "Allow Memact to receive allowed OS-level activity from a local helper.",
    grantsGraphRead: false,
    sensitive: true
  },
  "schema:write": {
    label: "Create schemas",
    description: "Allow Memact to form schema packets from retained activity.",
    grantsGraphRead: false
  },
  "graph:write": {
    label: "Write graph packets",
    description: "Allow Memact to store nodes, edges, and evidence packets created for this app.",
    grantsGraphRead: false
  },
  "memory:write": {
    label: "Write memory",
    description: "Allow Memact to persist retained graph evidence as memory.",
    grantsGraphRead: false
  },
  "memory:read_summary": {
    label: "Read memory summaries",
    description: "Allow the app to receive compact memory summaries.",
    grantsGraphRead: false
  },
  "memory:read_evidence": {
    label: "Read evidence cards",
    description: "Allow the app to receive evidence snippets and source metadata.",
    grantsGraphRead: false,
    sensitive: true
  },
  "memory:read_graph": {
    label: "Read graph objects",
    description: "Allow the app to receive permitted nodes and edges.",
    grantsGraphRead: true,
    sensitive: true
  }
})

export const DEFAULT_APP_SCOPES = Object.freeze([
  "capture:webpage",
  "schema:write",
  "graph:write",
  "memory:write",
  "memory:read_summary"
])

export const SENSITIVE_CAPTURE_RULES = Object.freeze({
  blockedHostKeywords: [
    "bank",
    "netbanking",
    "banking",
    "paypal",
    "stripe",
    "razorpay",
    "health",
    "medical",
    "hospital",
    "login",
    "password",
    "checkout",
    "payment",
    "mail",
    "inbox",
    "messages",
    "whatsapp",
    "telegram"
  ],
  blockedPathKeywords: [
    "login",
    "signin",
    "password",
    "reset",
    "checkout",
    "payment",
    "billing",
    "account",
    "messages",
    "inbox",
    "compose",
    "medical",
    "health"
  ],
  blockedFieldTypes: ["password", "tel", "email", "credit-card", "cc-number", "otp"]
})

export function normalizeScopes(scopes = []) {
  const known = new Set(Object.keys(SCOPE_DEFINITIONS))
  return [...new Set((Array.isArray(scopes) ? scopes : [])
    .map((scope) => String(scope || "").trim())
    .filter((scope) => known.has(scope)))]
}

export function unknownScopes(scopes = []) {
  const known = new Set(Object.keys(SCOPE_DEFINITIONS))
  return (Array.isArray(scopes) ? scopes : [])
    .map((scope) => String(scope || "").trim())
    .filter((scope) => scope && !known.has(scope))
}

export function hasAllScopes(available = [], required = []) {
  const availableSet = new Set(available)
  return required.every((scope) => availableSet.has(scope))
}
