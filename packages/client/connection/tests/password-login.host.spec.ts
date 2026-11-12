/** Username/password browser login. */

import { Readable } from 'node:stream'
import type { IncomingMessage } from 'node:http'
import { describe, expect, it } from 'vitest'
import type { CredentialProvider } from '@deepseek-ai/dsh-credentials'
import { BrowserAuth } from '../src/browser-auth.ts'
import { PasswordLogin, readLoginForm } from '../src/password-login.ts'
import type { ConnectionIndexResponse } from '../src/rpc.ts'
import { RecordCredentials } from './browser-credentials.ts'

interface ResponseState {
  status?: number
  headers?: Readonly<Record<string, string>>
  body?: string
}

function response(): { value: ConnectionIndexResponse; state: ResponseState } {
  const state: ResponseState = {}
  return {
    value: {
      writeHead(status, headers) {
        state.status = status
        if (headers !== undefined) state.headers = headers
      },
      end(body) {
        if (body !== undefined) state.body = body
      },
    },
    state,
  }
}

function formRequest(body: string, contentType = 'application/x-www-form-urlencoded'): IncomingMessage {
  const stream = Readable.from([Buffer.from(body, 'utf8')]) as unknown as IncomingMessage
  stream.headers = { 'content-type': contentType }
  return stream
}

describe('PasswordLogin', () => {
  it('rejects weak configuration', () => {
    expect(() => new PasswordLogin({ username: '', password: 'long-enough' })).toThrow(/username/)
    expect(() => new PasswordLogin({ username: 'admin', password: 'short' })).toThrow(/at least 8/)
  })

  it('accepts only the exact pair and locks a client after repeated failures', () => {
    const login = new PasswordLogin({ username: 'admin', password: 'correct horse' })
    expect(login.attempt('a', 'admin', 'correct horse')).toBe('ok')
    expect(login.attempt('a', 'Admin', 'correct horse')).toBe('invalid')
    expect(login.attempt('a', 'admin', 'correct hors')).toBe('invalid')
    for (let i = 0; i < 8; i += 1) login.attempt('a', 'admin', 'wrong')
    expect(login.attempt('a', 'admin', 'correct horse')).toBe('locked')
    expect(login.attempt('b', 'admin', 'correct horse')).toBe('ok')
  })

  it('escapes the error message in the rendered page', () => {
    const page = new PasswordLogin({ username: 'admin', password: 'correct horse' }).page('<script>')
    expect(page).toContain('&lt;script&gt;')
    expect(page).toContain('action="login"')
  })
})

describe('readLoginForm', () => {
  it('parses urlencoded bodies and refuses other content types or oversized bodies', async () => {
    const form = await readLoginForm(formRequest('username=admin&password=p%40ss'))
    expect(form?.get('username')).toBe('admin')
    expect(form?.get('password')).toBe('p@ss')
    expect(await readLoginForm(formRequest('{}', 'application/json'))).toBeUndefined()
    expect(await readLoginForm(formRequest(`password=${'x'.repeat(5000)}`))).toBeUndefined()
  })
})

describe('BrowserAuth login integration', () => {
  it('serves the login page to unauthenticated browsers and mints a working cookie on completion', async () => {
    const auth = await BrowserAuth.create({}, new RecordCredentials() as unknown as CredentialProvider, 30)
    const authority = '10.0.0.7:3080'

    const page = response()
    expect(auth.authorizeIndex({ method: 'GET', url: '/', headers: { host: authority } }, page.value, false, () => 'LOGIN')).toBe(false)
    expect(page.state.status).toBe(401)
    expect(page.state.headers?.['content-type']).toBe('text/html; charset=utf-8')
    expect(page.state.body).toBe('LOGIN')

    const done = response()
    expect(auth.completeLogin({ method: 'POST', url: '/login', headers: { host: authority } }, done.value)).toBe(true)
    expect(done.state.status).toBe(303)
    expect(done.state.headers?.location).toBe('./')
    const cookie = done.state.headers?.['set-cookie']?.split(';', 1)[0]
    expect(cookie).toBeDefined()
    expect(auth.isAuthenticated({ headers: { host: authority, cookie: cookie! } })).toBe(true)
    expect(auth.isAuthenticated({ headers: { host: '10.0.0.8:3080', cookie: cookie! } })).toBe(false)
  })

  it('falls back to the login page for a stale launch token', async () => {
    const auth = await BrowserAuth.create({}, new RecordCredentials() as unknown as CredentialProvider, 30)
    const res = response()
    expect(auth.authorizeIndex({ method: 'GET', url: '/?token=stale', headers: { host: 'localhost:3080' } }, res.value, false, () => 'LOGIN')).toBe(false)
    expect(res.state.status).toBe(401)
    expect(res.state.body).toBe('LOGIN')
  })

  it('keeps the plain 401 when login is disabled', async () => {
    const auth = await BrowserAuth.create({}, new RecordCredentials() as unknown as CredentialProvider, 30)
    const res = response()
    expect(auth.authorizeIndex({ method: 'GET', url: '/', headers: { host: '127.0.0.1:3080' } }, res.value)).toBe(false)
    expect(res.state.headers?.['content-type']).toBe('text/plain; charset=utf-8')
  })
})
