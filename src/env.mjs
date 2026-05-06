import fs from "node:fs"
import path from "node:path"

export function loadLocalEnv(filePath = path.resolve(process.cwd(), ".env")) {
  if (!fs.existsSync(filePath)) {
    return
  }

  const raw = fs.readFileSync(filePath, "utf8")
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith("#")) {
      continue
    }
    const separator = trimmed.indexOf("=")
    if (separator <= 0) {
      continue
    }
    const key = trimmed.slice(0, separator).trim()
    const value = trimmed.slice(separator + 1).trim().replace(/^["']|["']$/g, "")
    if (key && process.env[key] === undefined) {
      process.env[key] = value
    }
  }
}
