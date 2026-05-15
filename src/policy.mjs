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

export const CATEGORY_ALGORITHMS = Object.freeze({
  "web:news": {
    label: "News article understanding",
    capture: ["article url", "publisher/domain", "headline", "author when public", "published/updated time", "section headings", "selected article text", "visible citations and links"],
    understand: ["main claim", "supporting evidence", "named people and organizations", "topic trail", "stance or framing", "reading intent"],
    schema: ["article", "claim", "source", "topic", "user_attention"],
    memory: ["topics followed repeatedly", "sources revisited", "claims compared across articles", "attention shifts between related stories"]
  },
  "web:research": {
    label: "Research understanding",
    capture: ["document url", "title", "abstract or intro", "headings", "selected passages", "citations", "notes around the page"],
    understand: ["research question", "concepts being learned", "open questions", "evidence quality", "follow-up reading path"],
    schema: ["concept", "source", "question", "evidence", "learning_session"],
    memory: ["concepts revisited", "sources trusted", "unresolved questions", "study trajectory"]
  },
  "web:commerce": {
    label: "Shopping intent understanding",
    capture: ["product url", "title", "brand", "price when visible", "review snippets", "comparison attributes", "availability"],
    understand: ["purchase criteria", "tradeoffs", "preferred brands", "budget signals", "comparison intent"],
    schema: ["product", "attribute", "preference", "comparison", "decision"],
    memory: ["stable preferences", "repeated product categories", "budget patterns", "decision blockers"]
  },
  "web:social": {
    label: "Social post understanding",
    capture: ["public post url", "creator handle", "caption or post text", "thread context", "public engagement labels", "linked media metadata"],
    understand: ["topics followed", "creator affinity", "community context", "sentiment of interest", "reply or share intent"],
    schema: ["post", "creator", "topic", "community", "interest_signal"],
    memory: ["creators revisited", "communities followed", "topics that sustain attention", "public interaction patterns"]
  },
  "media:video": {
    label: "Video understanding",
    capture: ["video url", "title", "channel", "captions/transcript", "chapter markers", "watch position", "visible description"],
    understand: ["watched concepts", "important moments", "speaker claims", "learning or entertainment intent", "rewatch cues"],
    schema: ["video", "speaker", "claim", "moment", "topic"],
    memory: ["channels revisited", "topics watched deeply", "unfinished videos", "claims compared with other sources"]
  },
  "media:audio": {
    label: "Audio understanding",
    capture: ["episode url", "show name", "title", "transcript when available", "chapters", "speaker names"],
    understand: ["discussion topics", "speaker claims", "listening intent", "questions raised", "follow-up interests"],
    schema: ["episode", "speaker", "claim", "topic", "listening_session"],
    memory: ["shows revisited", "topics heard repeatedly", "speakers followed", "unfinished episodes"]
  },
  "ai:assistant": {
    label: "AI conversation understanding",
    capture: ["conversation title", "user prompts", "assistant answers when approved", "tool names", "task state", "linked files or urls"],
    understand: ["goal being pursued", "decisions made", "blockers", "working preferences", "next action"],
    schema: ["task", "decision", "preference", "blocker", "tool"],
    memory: ["recurring workflows", "preferences", "unfinished tasks", "decisions to remember"]
  },
  "dev:code": {
    label: "Developer workflow understanding",
    capture: ["repository name", "file path metadata", "issue or PR titles", "terminal command labels", "docs pages", "error messages"],
    understand: ["implementation goal", "bug context", "dependencies touched", "review risk", "next debugging step"],
    schema: ["repo", "file", "issue", "error", "implementation_step"],
    memory: ["project conventions", "repeated errors", "files frequently touched together", "review preferences"]
  },
  "work:docs": {
    label: "Document workflow understanding",
    capture: ["document title", "headings", "selected text", "comments", "linked docs", "edit sessions"],
    understand: ["document purpose", "open decisions", "stakeholders", "summary", "follow-up tasks"],
    schema: ["document", "decision", "stakeholder", "task", "summary"],
    memory: ["ongoing projects", "writing preferences", "recurring stakeholders", "open decisions"]
  }
})

export const STORAGE_PLAN = Object.freeze({
  default: {
    id: "local-first-memory",
    label: "Local-first memory",
    description: "Capture packets and raw evidence stay local by default. Apps receive only verified understanding allowed by consent."
  },
  future_user_cloud: {
    id: "user-owned-cloud-memory",
    label: "User-owned cloud memory",
    status: "planned",
    description: "The repository interface already supports remote adapters so users can later choose personal cloud storage without changing the API contract."
  }
})

export function suggestScopesForCategories(categories = []) {
  const cleanCategories = normalizeCategories(categories)
  const categorySet = new Set(cleanCategories)
  const suggested = new Set(["capture:webpage", "schema:write", "memory:read_summary"])

  if (categorySet.has("web:news") || categorySet.has("web:social") || categorySet.has("web:research")) {
    suggested.add("graph:write")
    suggested.add("memory:write")
  }
  if (categorySet.has("media:video") || categorySet.has("media:audio")) {
    suggested.add("capture:media")
  }
  if (categorySet.has("dev:code") || categorySet.has("ai:assistant") || categorySet.has("work:docs")) {
    suggested.add("memory:write")
  }
  if (categorySet.has("web:social") || categorySet.has("dev:code")) {
    suggested.add("memory:read_evidence")
  }

  return normalizeScopes([...suggested])
}

export function buildPermissionSuggestion(categories = []) {
  const cleanCategories = normalizeCategories(categories)
  const scopes = suggestScopesForCategories(cleanCategories)
  return {
    id: createStrategyId(scopes, cleanCategories),
    label: cleanCategories.includes("web:news") ? "Suggested for article understanding" : "Suggested permissions",
    description: "Selected by default from this app's activity categories. You can narrow or expand it before saving.",
    scopes,
    categories: cleanCategories
  }
}

export function buildUnderstandingStrategy({ scopes = [], categories = [] } = {}) {
  const cleanScopes = normalizeScopes(scopes)
  const cleanCategories = normalizeCategories(categories)
  const scopeSet = new Set(cleanScopes)
  const categoryAlgorithms = cleanCategories.map((category) => ({
    category,
    ...(CATEGORY_ALGORITHMS[category] || {})
  }))
  const captureInputs = unique(categoryAlgorithms.flatMap((algorithm) => algorithm.capture || []))
  const understandingOutputs = unique(categoryAlgorithms.flatMap((algorithm) => algorithm.understand || []))
  const schemaPackets = scopeSet.has("schema:write")
    ? unique(categoryAlgorithms.flatMap((algorithm) => algorithm.schema || []))
    : []
  const memoryObjects = (scopeSet.has("memory:write") || scopeSet.has("memory:read_summary") || scopeSet.has("memory:read_evidence") || scopeSet.has("memory:read_graph"))
    ? unique(categoryAlgorithms.flatMap((algorithm) => algorithm.memory || []))
    : []

  return {
    id: createStrategyId(cleanScopes, cleanCategories),
    product: "permissioned_understanding",
    tagline: "Understand what users are trying to do.",
    summary: buildStrategySummary(cleanScopes, cleanCategories),
    scopes: cleanScopes,
    categories: cleanCategories,
    category_algorithms: categoryAlgorithms,
    capture_plan: {
      allowed_inputs: captureInputs,
      local_only_raw_capture: true,
      blocked_sensitive_inputs: SENSITIVE_CAPTURE_RULES
    },
    understanding_plan: {
      outputs: understandingOutputs,
      schema_packets: schemaPackets,
      graph_write: scopeSet.has("graph:write"),
      memory_write: scopeSet.has("memory:write")
    },
    delivery_plan: {
      summaries: scopeSet.has("memory:read_summary"),
      evidence_cards: scopeSet.has("memory:read_evidence"),
      graph_objects: scopeSet.has("memory:read_graph")
    },
    storage_plan: STORAGE_PLAN
  }
}

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

function buildStrategySummary(scopes, categories) {
  const labels = categories.map((category) => CATEGORY_DEFINITIONS[category]?.label || category)
  const categoryText = labels.length ? labels.join(", ") : "approved activity"
  const delivery = scopes.includes("memory:read_graph")
    ? "summaries, evidence, and graph objects"
    : scopes.includes("memory:read_evidence")
      ? "summaries and evidence cards"
      : scopes.includes("memory:read_summary")
        ? "context summaries"
        : "write-only context updates"
  return `Use ${categoryText} to produce ${delivery} without exposing raw capture beyond the approved scopes.`
}

function createStrategyId(scopes, categories) {
  const raw = `${normalizeScopes(scopes).sort().join("+")}__${normalizeCategories(categories).sort().join("+")}`
  let hash = 0
  for (const char of raw) {
    hash = ((hash << 5) - hash + char.charCodeAt(0)) | 0
  }
  return `understanding_${Math.abs(hash).toString(36)}`
}

function unique(values = []) {
  return [...new Set(values.filter(Boolean))]
}
