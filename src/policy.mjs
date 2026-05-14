export const SCOPE_DEFINITIONS = Object.freeze({
  "capture:webpage": {
    label: "Use webpage evidence",
    description: "Allow Memact to use approved webpage evidence to understand activity for this app.",
    grantsGraphRead: false
  },
  "capture:media": {
    label: "Use media evidence",
    description: "Allow Memact to use approved captions, transcripts, and media context when available.",
    grantsGraphRead: false
  },
  "capture:device": {
    label: "Use device context",
    description: "Allow Memact to use approved OS-level activity signals from a local helper.",
    grantsGraphRead: false,
    sensitive: true
  },
  "schema:write": {
    label: "Create understanding schemas",
    description: "Allow Memact to turn retained evidence into schema packets for understanding.",
    grantsGraphRead: false
  },
  "graph:write": {
    label: "Write context graph",
    description: "Allow Memact to store nodes, edges, and evidence packets that describe user context for this app.",
    grantsGraphRead: false
  },
  "memory:write": {
    label: "Write memory",
    description: "Allow Memact to retain approved context as memory.",
    grantsGraphRead: false
  },
  "memory:read_summary": {
    label: "Read context summaries",
    description: "Allow the app to receive compact summaries of approved user context.",
    grantsGraphRead: false
  },
  "memory:read_evidence": {
    label: "Read evidence cards",
    description: "Allow the app to receive approved evidence snippets that explain the context.",
    grantsGraphRead: false,
    sensitive: true
  },
  "memory:read_graph": {
    label: "Read context graph",
    description: "Allow the app to receive permitted nodes and edges about approved user context.",
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

export const CATEGORY_DEFINITIONS = Object.freeze({
  "web:news": {
    label: "News articles",
    description: "News, politics, public affairs, and current-event pages."
  },
  "web:research": {
    label: "Research and learning",
    description: "Essays, papers, documentation, tutorials, and study material."
  },
  "web:commerce": {
    label: "Shopping and products",
    description: "Product pages, reviews, pricing pages, and purchase research."
  },
  "web:social": {
    label: "Social posts",
    description: "Public posts, feeds, replies, creator pages, and community content."
  },
  "media:video": {
    label: "Video and captions",
    description: "Videos, captions, transcripts, lectures, and long-form clips."
  },
  "media:audio": {
    label: "Audio and podcasts",
    description: "Podcasts, talks, songs with available text, and spoken audio context."
  },
  "ai:assistant": {
    label: "AI conversations",
    description: "Allowed conversations with AI tools such as assistants and copilots."
  },
  "dev:code": {
    label: "Code and developer work",
    description: "Repositories, docs, issues, pull requests, terminals, and coding tools."
  },
  "work:docs": {
    label: "Documents and notes",
    description: "Work documents, knowledge bases, notes, and writing tools."
  }
})

export const DEFAULT_APP_CATEGORIES = Object.freeze([
  "web:news",
  "web:research",
  "media:video",
  "ai:assistant",
  "dev:code"
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

export const SAFETY_RULES = Object.freeze({
  blockedUseCases: [
    "selling raw personal context",
    "surveillance without user consent",
    "credit, employment, insurance, or housing decisions",
    "manipulative targeting",
    "political persuasion targeting",
    "inferring highly sensitive traits without explicit user action"
  ],
  requiredDeveloperPromises: [
    "ask for only the scopes needed",
    "respect selected activity categories",
    "do not sell raw memory, context, or graph data",
    "show users where Memact is used",
    "let users disconnect access"
  ]
})

export const KNOWLEDGE_GRAPH_CONTRACT = Object.freeze({
  memoryUnit: "schema_packet",
  graphObjects: ["evidence", "content_unit", "node", "edge", "schema_packet"],
  nodeTypes: ["topic", "claim", "emotion", "source", "activity", "tool", "person", "action"],
  edgeTypes: ["seen_in", "repeated_with", "mentions", "shapes", "contradicts", "supports", "clicked_after", "searched_after"],
  authority: "Apps receive scoped understanding from approved memory. Memact keeps raw capture, filtering, and sensitive exclusions local-first."
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

export function normalizeCategories(categories = []) {
  const known = new Set(Object.keys(CATEGORY_DEFINITIONS))
  return [...new Set((Array.isArray(categories) ? categories : [])
    .map((category) => String(category || "").trim())
    .filter((category) => known.has(category)))]
}

export function unknownCategories(categories = []) {
  const known = new Set(Object.keys(CATEGORY_DEFINITIONS))
  return (Array.isArray(categories) ? categories : [])
    .map((category) => String(category || "").trim())
    .filter((category) => category && !known.has(category))
}

export function hasAllScopes(available = [], required = []) {
  const availableSet = new Set(available)
  return required.every((scope) => availableSet.has(scope))
}

export function hasAllCategories(available = [], required = []) {
  const availableSet = new Set(available)
  return required.every((category) => availableSet.has(category))
}
