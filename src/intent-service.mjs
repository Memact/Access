import { predictIntent as defaultPredictIntent } from "../../intent/src/engine.mjs"
import { normalizeCategories } from "./policy.mjs"
import { AccessError } from "./service.mjs"

const INTENT_SCOPE = "intent:predict"

export async function predictPermissionedIntent({
  service,
  apiKey,
  connectionId = "",
  requiredScopes = [],
  activityCategories = [],
  activities = [],
  predictIntent = defaultPredictIntent,
  now
} = {}) {
  if (!service) {
    throw new AccessError(500, "intent_service_missing", "Intent prediction is not configured.")
  }

  const requestedScopes = normalizeIntentScopes(requiredScopes)
  const access = await service.verifyApiAccess(apiKey, requestedScopes, [], connectionId)
  return buildPermissionedIntentResponse({ access, activityCategories, activities, predictIntent, now })
}

export function buildPermissionedIntentResponse({
  access,
  activityCategories = [],
  activities = [],
  predictIntent = defaultPredictIntent,
  now
} = {}) {
  if (!access?.allowed) {
    throw new AccessError(403, "access_denied", "Memact access denied.")
  }
  const approvedCategories = normalizeCategories(access.categories || [])
  const requestedCategories = normalizeCategories(activityCategories)
  const allowedCategorySet = new Set(
    requestedCategories.length
      ? approvedCategories.filter((category) => requestedCategories.includes(category))
      : approvedCategories
  )
  const approvedActivities = normalizeActivityList(activities)
    .filter((activity) => allowedCategorySet.has(String(activity.category || "").trim()))

  const intent = predictIntent({ activities: approvedActivities }, now ? { now } : {})

  return {
    allowed: true,
    schema_version: intent.schema_version,
    connection_id: access.connection_id,
    app: access.app,
    scopes: access.scopes,
    activity_categories: [...allowedCategorySet],
    filtered_activity_count: approvedActivities.length,
    intent
  }
}

function normalizeIntentScopes(requiredScopes = []) {
  const scopes = Array.isArray(requiredScopes) ? requiredScopes : []
  return [...new Set([INTENT_SCOPE, ...scopes].map((scope) => String(scope || "").trim()).filter(Boolean))]
}

function normalizeActivityList(activities = []) {
  return (Array.isArray(activities) ? activities : [])
    .filter((activity) => activity && typeof activity === "object")
    .map((activity) => ({
      id: String(activity.id || activity.activity_id || ""),
      type: String(activity.type || activity.activity_type || ""),
      category: String(activity.category || activity.activity_category || ""),
      label: String(activity.label || activity.title || activity.name || ""),
      url: String(activity.url || activity.source_url || ""),
      domain: String(activity.domain || ""),
      timestamp: String(activity.timestamp || activity.created_at || activity.recorded_at || ""),
      text: String(activity.text || activity.content_text || activity.excerpt || "")
    }))
    .filter((activity) => activity.id || activity.label)
}
