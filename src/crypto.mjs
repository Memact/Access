import crypto from "node:crypto"
import { promisify } from "node:util"

const scrypt = promisify(crypto.scrypt)
const PASSWORD_KEY_LENGTH = 64

export function randomId(prefix) {
  return `${prefix}_${crypto.randomUUID()}`
}

export function randomToken(prefix, byteLength = 32) {
  return `${prefix}_${crypto.randomBytes(byteLength).toString("base64url")}`
}

export function sha256(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex")
}

export async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("base64url")
  const derived = await scrypt(String(password), salt, PASSWORD_KEY_LENGTH)
  return `scrypt:${salt}:${Buffer.from(derived).toString("base64url")}`
}

export async function verifyPassword(password, storedHash) {
  const [algorithm, salt, hash] = String(storedHash || "").split(":")
  if (algorithm !== "scrypt" || !salt || !hash) return false
  const derived = await scrypt(String(password), salt, PASSWORD_KEY_LENGTH)
  const actual = Buffer.from(derived)
  const expected = Buffer.from(hash, "base64url")
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected)
}

export function hashSecret(secret) {
  return sha256(secret)
}
