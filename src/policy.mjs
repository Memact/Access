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

export const PERMISSION_REGISTRY = Object.freeze(Object.fromEntries(
  Object.entries(SCOPE_DEFINITIONS).map(([scope, definition]) => {
    const canCapture = scope.startsWith("capture:")
    const canRead = scope.startsWith("memory:read")
    return [scope, {
      ...definition,
      permission: scope,
      sensitivity: definition.sensitive ? "high" : canCapture || canRead ? "medium" : "standard",
      allowed_inputs: permissionInputs(scope),
      allowed_outputs: permissionOutputs(scope),
      storage_effects: permissionStorageEffects(scope)
    }]
  })
))

export const ACTIVITY_CATEGORY_REGISTRY = Object.freeze(Object.fromEntries(
  Object.entries(CATEGORY_DEFINITIONS).map(([category, definition]) => {
    const algorithm = CATEGORY_ALGORITHMS[category]
    return [category, {
      ...definition,
      category,
      capture_rules: algorithm.capture,
      extraction_rules: algorithm.understand,
      blocked_fields: categoryBlockedFields(category),
      default_memory_schema: algorithm.schema
    }]
  })
))

export const CATEGORY_PERMISSION_MATRIX = Object.freeze(buildCategoryPermissionMatrix())

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
  const suggested = new Set()
  for (const category of cleanCategories) {
    const matrix = CATEGORY_PERMISSION_MATRIX[category] || {}
    for (const [scope, status] of Object.entries(matrix)) {
      if (status === "recommended") suggested.add(scope)
    }
  }
  return normalizeScopes([...suggested])
}

export function buildPermissionSuggestion(categories = [], appPurpose = "") {
  const cleanCategories = normalizeCategories(categories)
  const scopes = suggestScopesForCategories(cleanCategories)
  const purpose = String(appPurpose || "").toLowerCase()
  if (/debug|audit|explain|citation|evidence|source/.test(purpose)) {
    scopes.push("memory:read_evidence")
  }
  return {
    id: createStrategyId(scopes, cleanCategories),
    label: cleanCategories.includes("web:news") ? "Suggested for article understanding" : "Suggested permissions",
    description: "Selected by default from this app's activity categories. You can narrow or expand it before saving.",
    scopes: normalizeScopes(scopes),
    categories: cleanCategories
  }
}

export function buildPresetSuggestions({ categories = [], appPurpose = "" } = {}) {
  const cleanCategories = normalizeCategories(categories)
  const primary = buildPermissionSuggestion(cleanCategories, appPurpose)
  const summaryOnly = normalizeScopes(["capture:webpage", cleanCategories.some((category) => category.startsWith("media:")) ? "capture:media" : "", "schema:write", "memory:read_summary"])
  const evidence = normalizeScopes([...primary.scopes, "memory:read_evidence"])
  return [
    primary,
    {
      id: createStrategyId(summaryOnly, cleanCategories),
      label: "Lean summary preset",
      description: "Smallest useful set: understand approved activity and return compact context only.",
      scopes: summaryOnly,
      categories: cleanCategories
    },
    {
      id: createStrategyId(evidence, cleanCategories),
      label: "Explainable preset",
      description: "Adds evidence cards so users and developers can see why Memact inferred something.",
      scopes: evidence,
      categories: cleanCategories
    }
  ].filter((preset, index, presets) => preset.scopes.length && presets.findIndex((item) => item.id === preset.id) === index)
}

export function validatePolicyRequest({ scopes = [], categories = [], appPurpose = "" } = {}) {
  const cleanScopes = normalizeScopes(scopes)
  const cleanCategories = normalizeCategories(categories)
  const warnings = []
  for (const category of cleanCategories) {
    const matrix = CATEGORY_PERMISSION_MATRIX[category] || {}
    for (const scope of cleanScopes) {
      const status = matrix[scope] || "blocked"
      if (status === "blocked") warnings.push(`${scope} is blocked for ${category}.`)
      if (status === "risky") warnings.push(`${scope} is risky for ${category}; use it only when the feature clearly explains why.`)
    }
  }
  const suggested = suggestScopesForCategories(cleanCategories)
  const extra = cleanScopes.filter((scope) => !suggested.includes(scope))
  if (extra.length && String(appPurpose || "").trim().length < 12) {
    warnings.push("Broad permissions need a clear app purpose so users understand why they are requested.")
  }
  return warnings
}

export function compilePolicy({ appId = "", scopes = [], categories = [], appPurpose = "" } = {}) {
  const cleanScopes = normalizeScopes(scopes)
  const cleanCategories = normalizeCategories(categories)
  const warnings = validatePolicyRequest({ scopes: cleanScopes, categories: cleanCategories, appPurpose })
  const strategy = buildUnderstandingStrategy({ scopes: cleanScopes, categories: cleanCategories })
  return {
    id: createPolicyId(appId, cleanScopes, cleanCategories, appPurpose),
    app_id: appId,
    product: "permissioned_understanding",
    tagline: "Understand users' digital activity.",
    purpose: String(appPurpose || "").trim().slice(0, 240),
    scopes: cleanScopes,
    categories: cleanCategories,
    permission_registry: Object.fromEntries(cleanScopes.map((scope) => [scope, PERMISSION_REGISTRY[scope]])),
    category_registry: Object.fromEntries(cleanCategories.map((category) => [category, ACTIVITY_CATEGORY_REGISTRY[category]])),
    category_permission_matrix: Object.fromEntries(cleanCategories.map((category) => [category, CATEGORY_PERMISSION_MATRIX[category]])),
    strategy,
    warnings,
    storage: STORAGE_PLAN,
    compiled_at: new Date().toISOString()
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
    tagline: "Understand users' digital activity.",
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

function buildCategoryPermissionMatrix() {
  const matrix = {}
  for (const category of Object.keys(CATEGORY_DEFINITIONS)) {
    matrix[category] = {}
    for (const scope of Object.keys(SCOPE_DEFINITIONS)) {
      matrix[category][scope] = permissionStatusForCategory(scope, category)
    }
  }
  return matrix
}

function permissionStatusForCategory(scope, category) {
  if (scope === "memory:read_graph") return "risky"
  if (scope === "capture:device" && !["dev:code", "ai:assistant", "work:docs"].includes(category)) return "risky"
  if (scope === "capture:media") return category.startsWith("media:") ? "recommended" : category === "web:social" ? "allowed" : "blocked"
  if (scope === "capture:webpage") return category.startsWith("web:") || ["ai:assistant", "dev:code", "work:docs"].includes(category) ? "recommended" : "allowed"
  if (scope === "schema:write" || scope === "memory:read_summary") return "recommended"
  if (scope === "graph:write" || scope === "memory:write") return ["web:news", "web:research", "web:social", "ai:assistant", "dev:code", "work:docs"].includes(category) ? "recommended" : "allowed"
  if (scope === "memory:read_evidence") return ["web:social", "dev:code"].includes(category) ? "recommended" : "allowed"
  return "allowed"
}

function permissionInputs(scope) {
  if (scope === "capture:webpage") return ["url", "domain", "title", "selected text", "visible page text", "page metadata"]
  if (scope === "capture:media") return ["captions", "transcripts", "chapter markers", "media page metadata"]
  if (scope === "capture:device") return ["active app", "window title", "visible UI text when local helper is enabled"]
  if (scope === "schema:write") return ["approved evidence packets", "content units", "candidate nodes and edges"]
  if (scope === "graph:write") return ["schema packets", "evidence links", "approved nodes and edges"]
  if (scope === "memory:write") return ["retained schema packets", "approved summaries", "evidence-backed context"]
  return ["compiled memory objects allowed by consent"]
}

function permissionOutputs(scope) {
  if (scope === "memory:read_summary") return ["compact context summaries"]
  if (scope === "memory:read_evidence") return ["evidence cards", "source snippets", "reasoning support"]
  if (scope === "memory:read_graph") return ["permitted nodes", "permitted edges", "graph metadata"]
  if (scope.startsWith("capture:")) return ["local evidence signals"]
  if (scope === "schema:write") return ["schema packets"]
  if (scope === "graph:write") return ["context graph writes"]
  if (scope === "memory:write") return ["retained memories"]
  return []
}

function permissionStorageEffects(scope) {
  if (scope.startsWith("capture:")) return ["local capture evidence may be created"]
  if (scope === "schema:write") return ["schema packets may be formed"]
  if (scope === "graph:write") return ["nodes, edges, and evidence links may be written"]
  if (scope === "memory:write") return ["approved context may be retained as memory"]
  return ["read-only delivery; no new storage by this permission alone"]
}

function categoryBlockedFields(category) {
  const shared = ["passwords", "otp codes", "payment details", "private messages", "medical identifiers"]
  if (category === "web:social") return [...shared, "non-public posts", "private follower lists"]
  if (category === "dev:code") return [...shared, "secrets", "tokens", "private keys", "environment files"]
  if (category === "web:commerce") return [...shared, "card numbers", "checkout forms", "billing addresses"]
  return shared
}

function createPolicyId(appId, scopes, categories, appPurpose) {
  const raw = `${appId}__${normalizeScopes(scopes).sort().join("+")}__${normalizeCategories(categories).sort().join("+")}__${String(appPurpose || "").trim().toLowerCase()}`
  let hash = 0
  for (const char of raw) {
    hash = ((hash << 5) - hash + char.charCodeAt(0)) | 0
  }
  return `policy_${Math.abs(hash).toString(36)}`
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
