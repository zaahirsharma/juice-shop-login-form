import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { randomBytes } from 'node:crypto'
import { DatabaseSync } from 'node:sqlite'
import { fileURLToPath } from 'node:url'
import bcrypt from 'bcryptjs'
import { validateLogin } from './public/validation.js'

export const demoEmail = 'student@example.com'
export const demoPassword = 'Student123!'
const publicFiles = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/app.js', ['app.js', 'text/javascript; charset=utf-8']],
  ['/validation.js', ['validation.js', 'text/javascript; charset=utf-8']],
  ['/styles.css', ['styles.css', 'text/css; charset=utf-8']]
])

export async function createApp ({ maxAttempts = 10, now = Date.now } = {}) {
  const db = new DatabaseSync(':memory:')
  db.exec('CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL)')
  const demoHash = await bcrypt.hash(demoPassword, 12)
  // Bound parameters keep user input separate from SQL syntax.
  db.prepare('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)').run(demoEmail, demoHash, 'customer')
  const findUser = db.prepare('SELECT id, email, password_hash, role FROM users WHERE email = ?')
  const sessions = new Map()
  const attempts = new Map()

  function json (res, status, body) {
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' })
    res.end(JSON.stringify(body))
  }

  const server = createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Referrer-Policy', 'no-referrer')
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    try {
      if (req.method === 'GET' && publicFiles.has(req.url)) {
        const [name, type] = publicFiles.get(req.url)
        const contents = await readFile(new URL(`./public/${name}`, import.meta.url))
        res.writeHead(200, { 'Content-Type': type })
        res.end(contents)
        return
      }
      if (req.method === 'GET' && req.url === '/api/session') {
        const token = /(?:^|;\s*)session=([a-f0-9]{64})(?:;|$)/.exec(req.headers.cookie || '')?.[1]
        const session = sessions.get(token)
        if (!session || session.expires <= now()) {
          if (token) sessions.delete(token)
          json(res, 401, { message: 'Please log in.' })
        } else {
          json(res, 200, { user: session.user })
        }
        return
      }
      if (req.method !== 'POST' || req.url !== '/api/login') {
        json(res, 404, { message: 'Page not found.' })
        return
      }
      if (req.headers.origin && req.headers.origin !== `http://${req.headers.host}`) {
        json(res, 403, { message: 'Cross-origin login is not allowed.' })
        return
      }
      if (req.headers['content-type']?.split(';')[0].trim() !== 'application/json') {
        json(res, 415, { message: 'Send a JSON request.' })
        return
      }
      const chunks = []
      let bytes = 0
      for await (const chunk of req) {
        bytes += chunk.length
        if (bytes > 4096) {
          json(res, 413, { message: 'Request is too large.' })
          return
        }
        chunks.push(chunk)
      }
      let body
      try {
        body = JSON.parse(Buffer.concat(chunks).toString('utf8'))
      } catch {
        json(res, 400, { message: 'Send valid JSON.' })
        return
      }
      if (!body || Array.isArray(body) || typeof body !== 'object' || Object.keys(body).some(key => !['email', 'password'].includes(key))) {
        json(res, 400, { message: 'Only email and password are accepted.' })
        return
      }
      const errors = validateLogin(body.email, body.password)
      if (Object.keys(errors).length) {
        json(res, 400, { message: 'Check the highlighted fields.', errors })
        return
      }
      const address = req.socket.remoteAddress
      for (const [key, value] of attempts) if (value.reset <= now()) attempts.delete(key)
      const attempt = attempts.get(address) || { count: 0, reset: now() + 60000 }
      attempt.count++
      attempts.set(address, attempt)
      if (attempt.count > maxAttempts) {
        res.setHeader('Retry-After', String(Math.ceil((attempt.reset - now()) / 1000)))
        json(res, 429, { message: 'Too many attempts. Wait one minute and try again.' })
        return
      }
      const user = findUser.get(body.email.trim().toLowerCase())
      // A dummy comparison also runs when the email is unknown.
      const matches = await bcrypt.compare(body.password, user?.password_hash || demoHash)
      if (!user || !matches) {
        json(res, 401, { message: 'Invalid email or password.' })
        return
      }
      for (const [key, value] of sessions) if (value.expires <= now()) sessions.delete(key)
      const safeUser = { id: user.id, email: user.email, role: user.role }
      const token = randomBytes(32).toString('hex')
      sessions.set(token, { user: safeUser, expires: now() + 900000 })
      res.setHeader('Set-Cookie', `session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=900`)
      json(res, 200, { message: 'Login successful.', user: safeUser })
    } catch {
      if (!res.headersSent) json(res, 500, { message: 'Unable to complete the request. Try again.' })
      else res.end()
    }
  })
  server.on('close', () => db.close())
  return server
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const server = await createApp()
  server.listen(Number(process.env.PORT || 3001), '127.0.0.1', () => {
    console.info(`Login form: http://localhost:${server.address().port}`)
  })
}
