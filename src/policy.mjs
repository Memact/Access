export const SCOPE_DEFINITIONS = Object.freeze({
  "capture:event_write": {
    label: "Send capture events",
    description: "Allow this app to send approved activity signals to Memact.",
    grantsGraphRead: false
  },
  "feature:list": {
    label: "List features",
    description: "Allow this app to see available Memact features.",
    grantsGraphRead: false
  },
  "feature:run": {
    label: "Run features",
    description: "Allow this app to run approved Memact features.",
    grantsGraphRead: false
  },
  "platform:bot": {
    label: "Use platform bot",
    description: "Allow a connected platform bot to use approved community memory for this app.",
    grantsGraphRead: false,
    sensitive: true
  },
  "context:read": {
    label: "Read personalization memory",
    description: "Allow this app to receive permitted Memact memory.",
    grantsGraphRead: false
  },
  "context:write": {
    label: "Write personalization memory",
    description: "Allow this app to add useful Memact memory for later personalization.",
    grantsGraphRead: false
  },
  "capture:webpage": {
    label: "Use webpage evidence",
    description: "Allow Memact to use approved webpage evidence to understand activity for this app.",
    grantsGraphRead: false
  },
  "capture:media": {
    label: "Use media evidence",
    description: "Allow Memact to use approved captions, transcripts, and media signals when available.",
    grantsGraphRead: false
  },
  "capture:device": {
    label: "Use device signals",
    description: "Allow Memact to use approved OS-level activity signals from a local helper.",
    grantsGraphRead: false,
    sensitive: true
  },
  "schema:write": {
    label: "Create schema packets",
    description: "Allow Memact to organize retained memory into schema packets.",
    grantsGraphRead: false
  },
  "schema:read": {
    label: "Read schema summaries",
    description: "Allow this app to read permitted schema packet summaries.",
    grantsGraphRead: false
  },
  "graph:write": {
    label: "Write memory graph",
    description: "Allow Memact to store nodes, edges, and evidence packets that describe user memory for this app.",
    grantsGraphRead: false
  },
  "memory:write": {
    label: "Write memory",
    description: "Allow Memact to retain approved activity as memory.",
    grantsGraphRead: false
  },
  "memory:read_summary": {
    label: "Read memory summaries",
    description: "Allow the app to receive compact summaries of approved user memory.",
    grantsGraphRead: false
  },
  "memory:read_evidence": {
    label: "Read evidence cards",
    description: "Allow the app to receive approved evidence snippets that explain the memory.",
    grantsGraphRead: false,
    sensitive: true
  },
  "memory:read_graph": {
    label: "Read memory graph",
    description: "Allow the app to receive permitted nodes and edges about approved user memory.",
    grantsGraphRead: true,
    sensitive: true
  },
  "schema:register": {
    label: "Register schemas",
    description: "Allow this app to register schema definitions and subschemas.",
    grantsGraphRead: false
  },
})

export const DEFAULT_APP_SCOPES = Object.freeze([
  "capture:webpage",
  "capture:event_write",
  "schema:write",
  "memory:write",
  "memory:read_summary",
  "feature:list"
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
    description: "Podcasts, talks, songs with available text, and spoken audio signals."
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
  },
  "shopping": {
    label: "Shopping",
    description: "Product research, preferences, comparisons, and shopping signals."
  },
  "learning": {
    label: "Learning",
    description: "Study, tutorials, courses, notes, and learning sessions."
  },
  "productivity": {
    label: "Productivity",
    description: "Tasks, workflows, calendars, docs, and work sessions."
  },
  "attention": {
    label: "Attention",
    description: "Focus, interruptions, sustained work, and cognitive load signals."
  },
  "preferences": {
    label: "Preferences",
    description: "User choices, likes, dislikes, and personalization preferences."
  },
  "fitness": {
    label: "Fitness",
    description: "Fitness goals, activity level, body metrics, hydration targets, and nutrition preferences."
  },
  "dietary_preferences": {
    label: "Dietary preferences",
    description: "Diet choices, allergies, restrictions, and nutrition preferences the user chooses to share."
  },
  "reading": {
    label: "Reading",
    description: "Article reading behavior such as opens, scroll depth, finish rate, skips, and summary use."
  },
  "news": {
    label: "News",
    description: "News articles and current-event reading signals."
  },
  "article": {
    label: "Articles",
    description: "Article pages, excerpts, topics, sources, and reading events."
  },
  "community:discord": {
    label: "Discord servers",
    description: "Server channels, public channel topics, and allowed community activity summaries."
  },
  "platform:discord": {
    label: "Discord platform",
    description: "Approved Discord bot activity, server metadata, and channel-level summaries."
  },
  "platform:reddit": {
    label: "Reddit platform",
    description: "Approved Reddit community activity, subreddit topics, and participation summaries."
  },
  "platform:telegram": {
    label: "Telegram platform",
    description: "Approved Telegram chat or group activity summaries."
  },
  "discord:server_activity": {
    label: "Discord server activity",
    description: "Approved server-level channel names, topics, and community activity summaries."
  },
  "reddit:community_activity": {
    label: "Reddit community activity",
    description: "Approved subreddit topics, public posts, and community participation summaries."
  },
  "telegram:chat_activity": {
    label: "Telegram chat activity",
    description: "Approved chat topics and group participation summaries."
  },
  "community": {
    label: "Communities",
    description: "Community spaces, server topics, group interests, and participation preferences."
  }
})

export const DEFAULT_APP_CATEGORIES = Object.freeze([
  "web:news",
  "web:research",
  "media:video",
  "ai:assistant",
  "dev:code",
  "preferences"
])

export const CATEGORY_ALGORITHMS = Object.freeze({
  "web:news": {
    label: "News article understanding",
    capture: ["article url", "publisher/domain", "headline", "author when public", "published/updated time", "section headings", "selected article text", "visible citations and links"],
    understand: ["main claim", "supporting evidence", "named people and organizations", "topic trail", "stance or framing", "reading purpose"],
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
    label: "Shopping preference understanding",
    capture: ["product url", "title", "brand", "price when visible", "review snippets", "comparison attributes", "availability"],
    understand: ["purchase criteria", "tradeoffs", "preferred brands", "budget signals", "comparison purpose"],
    schema: ["product", "attribute", "preference", "comparison", "decision"],
    memory: ["stable preferences", "repeated product categories", "budget patterns", "decision blockers"]
  },
  "web:social": {
    label: "Social post understanding",
    capture: ["public post url", "creator handle", "caption or post text", "thread signals", "public engagement labels", "linked media metadata"],
    understand: ["topics followed", "creator affinity", "community signal", "sentiment of interest", "reply or share intent"],
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
    understand: ["implementation goal", "bug detail", "dependencies touched", "review risk", "next debugging step"],
    schema: ["repo", "file", "issue", "error", "implementation_step"],
    memory: ["project conventions", "repeated errors", "files frequently touched together", "review preferences"]
  },
  "work:docs": {
    label: "Document workflow understanding",
    capture: ["document title", "headings", "selected text", "comments", "linked docs", "edit sessions"],
    understand: ["document purpose", "open decisions", "stakeholders", "summary", "follow-up tasks"],
    schema: ["document", "decision", "stakeholder", "task", "summary"],
    memory: ["ongoing projects", "writing preferences", "recurring stakeholders", "open decisions"]
  },
  "reading": {
    label: "Reading preference understanding",
    capture: ["article title", "topic", "source", "read time", "scroll depth", "finish event", "summary expand or collapse"],
    understand: ["topic interest", "skipped topics", "reading length preference", "summary style preference", "engagement pattern"],
    schema: ["reading_preferences", "preferred_topics", "skipped_topics", "summary_style_preference"],
    memory: ["reading preference memory", "repeat topics", "summary style preference", "article length preference"]
  },
  "news": {
    label: "News reading understanding",
    capture: ["headline", "topic", "publisher", "read time", "scroll depth", "finish event"],
    understand: ["topic interest", "source revisits", "drop-off pattern", "overview preference"],
    schema: ["reading_preferences", "source_trail", "topic_interest"],
    memory: ["news topics revisited", "preferred overview style", "sources revisited"]
  },
  "article": {
    label: "Article reading understanding",
    capture: ["article title", "excerpt", "topic", "source", "reading events"],
    understand: ["summary preference", "article length preference", "topic interest"],
    schema: ["reading_preferences", "summary_style_preference", "article_length_preference"],
    memory: ["article overview preference", "preferred topics", "skipped topics"]
  },
  "community:discord": {
    label: "Discord community personalization",
    capture: ["server id", "server name", "channel names", "channel topics", "allowed public channel activity summaries"],
    understand: ["channel interest", "muted topics", "community participation preference", "support or learning channel preference"],
    schema: ["community_preferences", "communication_preferences", "server_activity"],
    memory: ["preferred server channels", "topics to avoid", "community participation preferences"]
  },
  "platform:discord": {
    label: "Discord bot personalization",
    capture: ["bot install id", "server name", "channel names", "channel topics", "approved channel summaries"],
    understand: ["community topics", "preferred response style", "collaboration signals", "moderation-safe notes"],
    schema: ["community_preferences", "platform_preferences", "communication_preferences"],
    memory: ["community interests", "preferred response style", "platform bot preferences"]
  },
  "platform:reddit": {
    label: "Reddit community personalization",
    capture: ["subreddit name", "public topic labels", "approved public activity summaries"],
    understand: ["community interests", "topic preferences", "participation style"],
    schema: ["community_preferences", "platform_preferences"],
    memory: ["community interests", "topics followed", "topics avoided"]
  },
  "platform:telegram": {
    label: "Telegram bot personalization",
    capture: ["group name", "topic labels", "approved group activity summaries"],
    understand: ["group interests", "response style", "collaboration signals"],
    schema: ["community_preferences", "platform_preferences", "communication_preferences"],
    memory: ["community interests", "preferred response style"]
  },
  "discord:server_activity": {
    label: "Discord server activity personalization",
    capture: ["channel names", "channel topics", "approved server activity summaries"],
    understand: ["channel interest", "community participation preference", "support or learning channel preference"],
    schema: ["community_preferences", "server_activity"],
    memory: ["preferred server channels", "community participation preferences"]
  },
  "reddit:community_activity": {
    label: "Reddit community activity personalization",
    capture: ["subreddit topics", "approved public activity summaries"],
    understand: ["topic interests", "community preference", "participation style"],
    schema: ["community_preferences", "platform_preferences"],
    memory: ["topics followed", "topics to avoid"]
  },
  "telegram:chat_activity": {
    label: "Telegram chat activity personalization",
    capture: ["group topics", "approved chat activity summaries"],
    understand: ["topic interests", "response style", "collaboration signals"],
    schema: ["community_preferences", "platform_preferences"],
    memory: ["community interests", "preferred response style"]
  },
  "community": {
    label: "Community personalization",
    capture: ["community name", "public topic labels", "allowed participation summaries", "channel or group metadata"],
    understand: ["community interest", "topics followed", "topics skipped", "participation style"],
    schema: ["community_preferences", "communication_preferences"],
    memory: ["community preferences", "topics followed", "topics to avoid"]
  }
})

const DEFAULT_CATEGORY_ALGORITHM = Object.freeze({
  label: "Context understanding",
  capture: ["event category", "source app", "timestamp", "visible label", "permitted metadata"],
  understand: ["topic", "action", "preference", "purpose"],
  schema: ["activity", "topic", "preference", "source"],
  memory: ["stable preferences", "repeated topics", "useful memory"]
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
    const algorithm = CATEGORY_ALGORITHMS[category] || DEFAULT_CATEGORY_ALGORITHM
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
    description: "Capture packets and sensitive evidence stay local by default. Apps receive only memory allowed by consent."
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
    label: cleanCategories.includes("web:news") ? "Suggested for article personalization" : "Suggested permissions",
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
      description: "Smallest useful set: understand approved activity and return compact memory only.",
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
    product: "memact",
    tagline: "Personalization made better",
    subtagline: "with Memact",
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
    product: "memact",
    tagline: "Personalization made better",
    subtagline: "with Memact",
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
    "selling raw personal memory",
    "surveillance without user consent",
    "credit, employment, insurance, or housing decisions",
    "manipulative targeting",
    "political persuasion targeting",
    "inferring highly sensitive traits without explicit user action"
  ],
  requiredDeveloperPromises: [
    "ask for only the scopes needed",
    "respect selected activity categories",
    "do not sell raw memory or graph data",
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
        ? "memory summaries"
        : "write-only memory updates"
  return `Use ${categoryText} to produce ${delivery} inside the selected scopes.`
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
  if (scope === "capture:event_write" || scope === "feature:list") return "recommended"
  if (scope === "platform:bot") return category.startsWith("platform:") || category.startsWith("discord:") || category.startsWith("reddit:") || category.startsWith("telegram:") || category === "community:discord" ? "recommended" : "blocked"
  if (scope === "schema:register") return ["reading", "news", "article", "community", "community:discord", "web:news", "web:research"].includes(category) ? "allowed" : "risky"
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
  if (scope === "memory:write") return ["retained schema packets", "approved summaries", "evidence-backed memory"]
  return ["compiled memory objects allowed by consent"]
}

function permissionOutputs(scope) {
  if (scope === "memory:read_summary") return ["compact memory summaries"]
  if (scope === "memory:read_evidence") return ["evidence cards", "source snippets", "reasoning support"]
  if (scope === "memory:read_graph") return ["permitted nodes", "permitted edges", "graph metadata"]
  if (scope.startsWith("capture:")) return ["local evidence signals"]
  if (scope === "schema:write") return ["schema packets"]
  if (scope === "graph:write") return ["memory graph writes"]
  if (scope === "memory:write") return ["retained memories"]
  return []
}

function permissionStorageEffects(scope) {
  if (scope.startsWith("capture:")) return ["local capture evidence may be created"]
  if (scope === "schema:write") return ["schema packets may be formed"]
  if (scope === "graph:write") return ["nodes, edges, and evidence links may be written"]
  if (scope === "memory:write") return ["approved activity may be retained as memory"]
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
