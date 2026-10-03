import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { JSDOM } from 'jsdom'
import { setupLogin, renderFeedback } from '../public/app.js'
import { validateLogin } from '../public/validation.js'

const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8')
const page = () => new JSDOM(html, { url: 'http://localhost:3001' })
const settle = () => new Promise(resolve => setImmediate(resolve))
function submit (dom, email, password) {
  dom.window.document.getElementById('email').value = email
  dom.window.document.getElementById('password').value = password
  dom.window.document.getElementById('login-form').dispatchEvent(new dom.window.Event('submit', { cancelable: true }))
}

test('shared validation meets the assignment rules and preserves password whitespace', () => {
  assert.deepEqual(validateLogin('student@example.com', 'Student123!'), {})
  assert.deepEqual(validateLogin('student@example.com', '        '), {})
  assert.ok(validateLogin('', '').email)
  assert.ok(validateLogin('student', '1234567').password)
})

test('empty submission never calls the server and focuses the first invalid field', () => {
  const dom = page()
  let requests = 0
  setupLogin(dom.window.document, async () => { requests++ })
  submit(dom, '', '')
  assert.equal(requests, 0)
  assert.equal(dom.window.document.activeElement.id, 'email')
  assert.equal(dom.window.document.getElementById('email').getAttribute('aria-invalid'), 'true')
  assert.equal(dom.window.document.getElementById('email-error').textContent, 'Enter your email.')
  dom.window.close()
})

test('missing @ and short password are rejected in the browser', () => {
  const dom = page()
  setupLogin(dom.window.document, () => assert.fail('No request should be made'))
  submit(dom, 'student.example.com', 'short')
  assert.match(dom.window.document.getElementById('email-error').textContent, /containing @/)
  assert.equal(dom.window.document.getElementById('password-error').textContent, 'Use at least 8 characters.')
  dom.window.close()
})

test('XSS is rendered as literal text even without depending on CSP', () => {
  const dom = page()
  const document = dom.window.document
  const payload = '<img src=x onerror=alert("xss")>@example.com'
  renderFeedback(document, 'Invalid email or password.', payload)
  const output = document.getElementById('submitted-email')
  assert.equal(output.textContent, `Submitted email: ${payload}`)
  assert.equal(output.children.length, 0)
  assert.equal(document.querySelector('img'), null)
  dom.window.close()
})

test('submit disables duplicates and restores the button after success', async () => {
  const dom = page()
  let resolveRequest; let requests = 0
  setupLogin(dom.window.document, () => {
    requests++
    return new Promise(resolve => { resolveRequest = resolve })
  })
  submit(dom, 'student@example.com', 'Student123!')
  submit(dom, 'student@example.com', 'Student123!')
  assert.equal(requests, 1)
  assert.equal(dom.window.document.getElementById('login-button').disabled, true)
  assert.equal(dom.window.document.getElementById('login-form').getAttribute('aria-busy'), 'true')
  resolveRequest({ ok: true, json: async () => ({ message: 'Login successful.' }) })
  await settle()
  assert.equal(dom.window.document.getElementById('login-button').disabled, false)
  assert.equal(dom.window.document.getElementById('password').value, '')
  assert.equal(dom.window.document.getElementById('status').textContent, 'Login successful.')
  dom.window.close()
})

test('server field errors are displayed and focus the affected field', async () => {
  const dom = page()
  setupLogin(dom.window.document, async () => ({
    ok: false, json: async () => ({ message: 'Check the highlighted fields.', errors: { password: 'Use at least 8 characters.' } })
  }))
  submit(dom, 'student@example.com', 'Student123!')
  await settle()
  assert.equal(dom.window.document.activeElement.id, 'password')
  assert.equal(dom.window.document.getElementById('password').getAttribute('aria-invalid'), 'true')
  dom.window.close()
})

test('network failure preserves fields and supports retry', async () => {
  const dom = page()
  let requests = 0
  setupLogin(dom.window.document, async () => {
    if (++requests === 1) throw new Error('Offline')
    return { ok: true, json: async () => ({ message: 'Login successful.' }) }
  })
  submit(dom, 'student@example.com', 'Student123!')
  await settle()
  assert.match(dom.window.document.getElementById('status').textContent, /Cannot reach the server/)
  assert.equal(dom.window.document.getElementById('password').value, 'Student123!')
  assert.equal(dom.window.document.getElementById('login-button').disabled, false)
  submit(dom, 'student@example.com', 'Student123!')
  await settle()
  assert.equal(dom.window.document.getElementById('status').textContent, 'Login successful.')
  dom.window.close()
})

test('password is masked initially and has an accessible show/hide toggle', () => {
  const dom = page()
  setupLogin(dom.window.document, async () => {})
  const input = dom.window.document.getElementById('password')
  const button = dom.window.document.getElementById('toggle-password')
  assert.equal(input.type, 'password')
  button.click()
  assert.equal(input.type, 'text')
  assert.equal(button.getAttribute('aria-label'), 'Hide password')
  button.click()
  assert.equal(input.type, 'password')
  assert.equal(button.getAttribute('aria-label'), 'Show password')
  dom.window.close()
})
