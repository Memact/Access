import { existsSync } from "node:fs"
import path from "node:path"
import { fileURLToPath, pathToFileURL } from "node:url"

const here = path.dirname(fileURLToPath(import.meta.url))
let cachedPredictIntent = null

export async function loadPredictIntent() {
  if (cachedPredictIntent) return cachedPredictIntent

  const attempts = [
    () => import("memact-intent"),
    ...enginePathCandidates().map((candidate) => () => import(pathToFileURL(candidate).href))
  ]

  const errors = []
  for (const attempt of attempts) {
    try {
      const module = await attempt()
      if (typeof module.predictIntent === "function") {
        cachedPredictIntent = module.predictIntent
        return cachedPredictIntent
      }
      errors.push("module did not export predictIntent")
    } catch (error) {
      errors.push(error?.code || error?.message || String(error))
    }
  }

  throw new Error(
    `Memact Intent engine is unavailable. Install/link the memact-intent package or set MEMACT_INTENT_ENGINE_PATH to Intent/src/engine.mjs. Tried: ${errors.join("; ")}`
  )
}

function enginePathCandidates() {
  const candidates = []
  if (process.env.MEMACT_INTENT_ENGINE_PATH) {
    candidates.push(path.resolve(process.env.MEMACT_INTENT_ENGINE_PATH))
  }

  candidates.push(
    path.resolve(here, "../../Intent/src/engine.mjs"),
    path.resolve(here, "../../intent/src/engine.mjs")
  )

  return [...new Set(candidates)].filter((candidate) => existsSync(candidate))
}
