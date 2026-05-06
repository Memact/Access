import nodemailer from "nodemailer"

export function createEmailNotifierFromEnv(env = process.env) {
  const host = String(env.MEMACT_ACCESS_SMTP_HOST || "").trim()
  if (!host) return new NoopEmailNotifier()

  const port = Number(env.MEMACT_ACCESS_SMTP_PORT || 587)
  const secure = String(env.MEMACT_ACCESS_SMTP_SECURE || "false").toLowerCase() === "true"
  const user = String(env.MEMACT_ACCESS_SMTP_USER || "").trim()
  const pass = String(env.MEMACT_ACCESS_SMTP_PASS || "")
  const from = String(env.MEMACT_ACCESS_EMAIL_FROM || "Memact <no-reply@memact.com>").trim()
  if (!isConfiguredSecret(user) || !isConfiguredSecret(pass)) {
    return new NoopEmailNotifier("smtp_credentials_missing")
  }

  const transport = nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user, pass }
  })

  return {
    async send({ to, subject, text }) {
      await transport.sendMail({ from, to, subject, text })
      return { sent: true, channel: "smtp" }
    }
  }
}

export class NoopEmailNotifier {
  constructor(reason = "smtp_not_configured") {
    this.reason = reason
  }

  async send() {
    return { sent: false, channel: "none", reason: this.reason }
  }
}

function isConfiguredSecret(value) {
  const text = String(value || "").trim()
  return Boolean(text) && !text.startsWith("your_") && !text.includes("<")
}
