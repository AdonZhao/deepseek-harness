/**
 * Real-listener coverage of the password login: a webserver bound to the
 * wildcard address, the Connection plugin with `login` configured, and a
 * fallback that answers the index through Connection's browser authentication.
 */

import { request as httpRequest } from 'node:http'
import { networkInterfaces } from 'node:os'
import { afterEach, describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import HttpServer from '@deepseek-ai/dsh-host-webserver'
import { apply, inject, type HostConnectionHandle } from '../src/index.ts'
import { provideBrowserCredentials } from './browser-credentials.ts'

interface Reply {
  status: number
  headers: Record<string, string | string[] | undefined>
  body: string
}

interface SendInit {
  host: string
  path?: string
  method?: string
  body?: string
  headers?: Record<string, string>
}

function send(port: number, init: SendInit): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      host: '127.0.0.1',
      port,
      path: init.path ?? '/',
      method: init.method ?? 'GET',
      headers: { host: init.host, ...init.headers },
    }, (res) => {
      const chunks: Buffer[] = []
      res.on('data', (chunk: Buffer) => { chunks.push(chunk) })
      res.on('end', () => {
        resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') })
      })
    })
    req.on('error', reject)
    req.end(init.body)
  })
}

function form(fields: Record<string, string>): { body: string; headers: Record<string, string> } {
  return { body: new URLSearchParams(fields).toString(), headers: { 'content-type': 'application/x-www-form-urlencoded' } }
}

/** A non-loopback IPv4 address of this machine, as a wildcard listener serves it. */
function interfaceAddress(): string {
  for (const entries of Object.values(networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.family === 'IPv4' && !entry.internal) return entry.address
    }
  }
  return '127.0.0.1'
}

const disposers: (() => Promise<void>)[] = []
afterEach(async () => {
  for (const dispose of disposers.splice(0).reverse()) await dispose()
})

async function boot(): Promise<number> {
  const ctx = new Context()
  provideBrowserCredentials(ctx)
  const server = ctx.plugin(HttpServer, HttpServer.Config({ host: '0.0.0.0', port: 0 }))
  await server.await()
  disposers.push(() => server.dispose())
  const connection = ctx.plugin({ inject: [...inject], apply }, {
    trustedHosts: ['remote.example'],
    login: { username: 'admin', password: 'correct horse' },
  })
  await connection.await()
  disposers.push(() => connection.dispose())
  ctx.webServer.registerFallback((req, res) => {
    const handle = ctx.get('connection') as HostConnectionHandle
    if (handle.authorizeIndex(req, res)) res.writeHead(200).end('APP')
  })
  const port = ctx.webServer.port
  if (port === undefined) throw new Error('listener did not bind')
  return port
}

describe('password login over a wildcard listener', () => {
  it('walks the login page, rejection, session cookie, and API admission', async () => {
    const port = await boot()
    const host = `${interfaceAddress()}:${String(port)}`

    const page = await send(port, { host })
    expect(page.status).toBe(401)
    expect(page.body).toContain('action="login"')
    // no-referrer would make browsers post the form with `Origin: null`.
    expect(page.headers['referrer-policy']).toBe('same-origin')
    expect(page.body).toContain('content="same-origin"')

    const wrong = await send(port, { host, path: '/login', method: 'POST', ...form({ username: 'admin', password: 'nope' }) })
    expect(wrong.status).toBe(401)
    expect(wrong.body).toContain('Incorrect username or password')

    const ok = await send(port, { host, path: '/login', method: 'POST', ...form({ username: 'admin', password: 'correct horse' }) })
    expect(ok.status).toBe(303)
    expect(ok.headers.location).toBe('./')
    const setCookie = ok.headers['set-cookie']
    const cookie = (Array.isArray(setCookie) ? setCookie[0] : setCookie)?.split(';', 1)[0]
    expect(cookie).toBeDefined()

    const app = await send(port, { host, headers: { cookie: cookie! } })
    expect(app.status).toBe(200)
    expect(app.body).toBe('APP')

    const api = await send(port, { host, path: '/api/does-not-exist', headers: { cookie: cookie! } })
    expect([401, 403]).not.toContain(api.status)
    const anonymousApi = await send(port, { host, path: '/api/does-not-exist' })
    expect(anonymousApi.status).toBe(401)
  })

  it('admits declared trusted hosts and fences unknown Host or cross-origin submissions', async () => {
    const port = await boot()

    expect((await send(port, { host: 'remote.example' })).body).toContain('action="login"')

    const rebound = await send(port, { host: 'evil.example' })
    expect(rebound.status).toBe(403)
    expect(rebound.body).toContain('evil.example is not trusted')
    expect(rebound.body).not.toContain('action="login"')
    const reboundLogin = await send(port, { host: 'evil.example', path: '/login', method: 'POST', ...form({ username: 'admin', password: 'correct horse' }) })
    expect(reboundLogin.status).toBe(403)

    const crossSite = await send(port, {
      host: 'remote.example',
      path: '/login',
      method: 'POST',
      body: form({ username: 'admin', password: 'correct horse' }).body,
      headers: { 'content-type': 'application/x-www-form-urlencoded', 'origin': 'https://attacker.example' },
    })
    expect(crossSite.status).toBe(403)

    expect((await send(port, { host: 'remote.example', path: '/login' })).status).toBe(405)
  })
})
