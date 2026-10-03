import { after, before, test } from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createApp, demoEmail, demoPassword } from '../server.js'

let server, base
before(async () => {
  server = await createApp({ maxAttempts: 50 })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  base = `http://127.0.0.1:${server.address().port}`
})
after(async () => {
  server.close()
  await once(server, 'close')
})
const login = (body, headers = {}) => fetch(`${base}/api/login`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', ...headers },
  body: JSON.stringify(body)
})

test('serves the form and restrictive browser headers', async () => {
  const response = await fetch(base)
  assert.equal(response.status, 200)
  assert.match(await response.text(), /<form id="login-form" novalidate>/)
  assert.match(response.headers.get('content-security-policy'), /script-src 'self'/)
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff')
})

test('valid credentials create a server-side session without exposing the hash', async () => {
  const response = await login({ email: demoEmail, password: demoPassword })
  assert.equal(response.status, 200)
  const body = await response.json()
  assert.deepEqual(body.user, { id: 1, email: demoEmail, role: 'customer' })
  assert.equal('password_hash' in body.user, false)
  const cookie = response.headers.get('set-cookie')
  assert.match(cookie, /HttpOnly; SameSite=Strict/)
  const session = await fetch(`${base}/api/session`, { headers: { Cookie: cookie.split(';')[0] } })
  assert.equal(session.status, 200)
  assert.deepEqual((await session.json()).user, body.user)
})

test('server rejects empty, malformed, wrong-type, short and oversized values directly', async () => {
  for (const body of [
    {}, { email: '', password: '' },
    { email: 'student.example.com', password: demoPassword },
    { email: demoEmail, password: 'short' },
    { email: ['student@example.com'], password: demoPassword },
    { email: demoEmail, password: 12345678 },
    { email: demoEmail, password: 'a'.repeat(73) },
    { email: demoEmail, password: '🔒'.repeat(19) },
    { email: `${'a'.repeat(254)}@`, password: demoPassword }
  ]) assert.equal((await login(body)).status, 400)
})

test('SQL injection cannot log in, even with the real password of another user', async () => {
  for (const email of ["student@example.com' OR 1=1--", "admin@juice-sh.op'--"]) {
    const response = await login({ email, password: demoPassword })
    assert.equal(response.status, 401)
    assert.equal(response.headers.get('set-cookie'), null)
    assert.deepEqual(await response.json(), { message: 'Invalid email or password.' })
  }
})

test('XSS payload is not reflected into the response or authenticated', async () => {
  const response = await login({ email: '<img src=x onerror=alert("xss")>@example.com', password: demoPassword })
  assert.equal(response.status, 401)
  assert.equal(response.headers.get('set-cookie'), null)
  assert.deepEqual(await response.json(), { message: 'Invalid email or password.' })
})

test('client-supplied administrator role is rejected', async () => {
  const response = await login({ email: demoEmail, password: demoPassword, role: 'admin' })
  assert.equal(response.status, 400)
})

test('unknown emails and wrong passwords get the same generic response', async () => {
  const unknown = await login({ email: 'nobody@example.com', password: demoPassword })
  const incorrect = await login({ email: demoEmail, password: 'wrongpass123' })
  assert.equal(unknown.status, 401)
  assert.equal(incorrect.status, 401)
  assert.deepEqual(await unknown.json(), await incorrect.json())
})

test('rejects untrusted origin, non-JSON, invalid JSON and oversized bodies', async () => {
  assert.equal((await login({ email: demoEmail, password: demoPassword }, { Origin: 'http://evil.example' })).status, 403)
  assert.equal((await login({}, { 'Content-Type': 'text/plain' })).status, 415)
  assert.equal((await fetch(`${base}/api/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{'
  })).status, 400)
  assert.equal((await login({ email: 'a'.repeat(5000), password: demoPassword })).status, 413)
})

test('unauthenticated sessions and unlisted paths are blocked', async () => {
  assert.equal((await fetch(`${base}/api/session`)).status, 401)
  assert.equal((await fetch(`${base}/server.js`)).status, 404)
})

test('attempt limit returns 429 and expires after one minute', async () => {
  let time = 100000
  const limited = await createApp({ maxAttempts: 1, now: () => time })
  limited.listen(0, '127.0.0.1')
  await once(limited, 'listening')
  try {
    const url = `http://127.0.0.1:${limited.address().port}/api/login`
    const request = () => fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: demoEmail, password: 'wrongpass123' })
    })
    assert.equal((await request()).status, 401)
    const blocked = await request()
    assert.equal(blocked.status, 429)
    assert.equal(blocked.headers.get('retry-after'), '60')
    time += 60001
    assert.equal((await request()).status, 401)
  } finally {
    limited.close()
    await once(limited, 'close')
  }
})

test('session expires after fifteen minutes', async () => {
  let time = 100000
  const expiring = await createApp({ now: () => time })
  expiring.listen(0, '127.0.0.1')
  await once(expiring, 'listening')
  try {
    const url = `http://127.0.0.1:${expiring.address().port}`
    const response = await fetch(`${url}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: demoEmail, password: demoPassword })
    })
    time += 900001
    const session = await fetch(`${url}/api/session`, {
      headers: { Cookie: response.headers.get('set-cookie').split(';')[0] }
    })
    assert.equal(session.status, 401)
  } finally {
    expiring.close()
    await once(expiring, 'close')
  }
})
