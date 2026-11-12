/**
 * Optional username/password login for remotely reachable Web deployments.
 *
 * When configured, an unauthenticated index request receives a login form
 * instead of the bare 401, and `POST /login` exchanges matching credentials
 * for the same signed browser-session cookie the launch token mints. The
 * launch token printed on the server console keeps working.
 */

import { createHash, timingSafeEqual } from 'node:crypto'
import type { IncomingMessage } from 'node:http'

/** Exact route answering the login form submission. */
export const LOGIN_PATH = '/login'

/** Largest accepted urlencoded login body. */
const MAX_LOGIN_BODY_BYTES = 4096
/** Failures one client address may make inside {@link FAILURE_WINDOW_MILLISECONDS}. */
const MAX_FAILURES = 10
const FAILURE_WINDOW_MILLISECONDS = 15 * 60 * 1000

/** Login credentials as configured; the password never leaves this process. */
export interface PasswordLoginConfig {
  username: string
  password: string
}

/** Outcome of one login attempt. */
export type LoginAttempt = 'ok' | 'invalid' | 'locked'

function digest(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest()
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll('\'', '&#39;')
}

/**
 * Read a small `application/x-www-form-urlencoded` body.
 * @param req - incoming POST request.
 * @returns the parsed fields, or undefined for a wrong content type or an oversized body.
 */
export async function readLoginForm(req: IncomingMessage): Promise<URLSearchParams | undefined> {
  const type = (req.headers['content-type'] ?? '').split(';')[0]?.trim().toLowerCase()
  if (type !== 'application/x-www-form-urlencoded') return undefined
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of req as AsyncIterable<Buffer>) {
    size += chunk.byteLength
    if (size > MAX_LOGIN_BODY_BYTES) return undefined
    chunks.push(chunk)
  }
  return new URLSearchParams(Buffer.concat(chunks).toString('utf8'))
}

/** Credential check with a per-client failure budget. */
export class PasswordLogin {
  private readonly username: Buffer
  private readonly password: Buffer
  private readonly failures = new Map<string, { count: number; resetAt: number }>()

  constructor(config: PasswordLoginConfig) {
    if (config.username.length === 0) throw new Error('client-connection: login.username must not be empty')
    if (config.password.length < 8) throw new Error('client-connection: login.password must be at least 8 characters')
    this.username = digest(config.username)
    this.password = digest(config.password)
  }

  /**
   * Check one submission. Both fields are always compared in constant time.
   * @param client - remote address used for the failure budget.
   * @param username - submitted user name.
   * @param password - submitted password.
   * @returns the verdict and, on success, the redirect the caller should send.
   */
  attempt(client: string, username: string, password: string): LoginAttempt {
    const now = Date.now()
    const record = this.failures.get(client)
    if (record !== undefined && record.resetAt <= now) this.failures.delete(client)
    const current = this.failures.get(client)
    if (current !== undefined && current.count >= MAX_FAILURES) return 'locked'
    const userOk = timingSafeEqual(digest(username), this.username)
    const passwordOk = timingSafeEqual(digest(password), this.password)
    if (userOk && passwordOk) {
      this.failures.delete(client)
      return 'ok'
    }
    if (current === undefined) this.failures.set(client, { count: 1, resetAt: now + FAILURE_WINDOW_MILLISECONDS })
    else current.count += 1
    return 'invalid'
  }

  /**
   * Render the self-contained login document. The form posts to the
   * directory-relative `login`, so a prefix-stripping proxy mount still works.
   * @param error - message shown above the form.
   * @returns the login document as HTML.
   */
  page(error?: string): string {
    const message = error === undefined ? '' : `<p class="error">${escapeHtml(error)}</p>`
    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="same-origin">
<title>DeepSeek Harness · Sign in</title>
<style>
  :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
  body { display: grid; place-items: center; min-height: 100vh; margin: 0; }
  form { display: grid; gap: 12px; width: min(320px, 90vw); }
  h1 { font-size: 20px; margin: 0 0 8px; }
  input, button { font: inherit; padding: 8px 10px; border-radius: 6px; border: 1px solid #8884; }
  button { cursor: pointer; background: #4d6bfe; color: #fff; border: none; }
  .error { color: #d33; margin: 0; }
</style>
</head>
<body>
<form method="post" action="login" autocomplete="on">
  <h1>DeepSeek Harness</h1>
  ${message}
  <input name="username" autocomplete="username" placeholder="Username" required autofocus>
  <input name="password" type="password" autocomplete="current-password" placeholder="Password" required>
  <button type="submit">Sign in</button>
</form>
</body>
</html>
`
  }
}
