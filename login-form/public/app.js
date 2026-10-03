import { validateLogin } from './validation.js'

export function renderFeedback (document, message, email = '') {
  document.getElementById('status').textContent = message
  document.getElementById('submitted-email').textContent = email ? `Submitted email: ${email}` : ''
}

export function setupLogin (document, fetchRequest = globalThis.fetch.bind(globalThis)) {
  const form = document.getElementById('login-form')
  const email = document.getElementById('email')
  const password = document.getElementById('password')
  const button = document.getElementById('login-button')
  const toggle = document.getElementById('toggle-password')
  let busy = false

  function showErrors (errors) {
    for (const field of [email, password]) {
      field.setAttribute('aria-invalid', String(Boolean(errors[field.id])))
      document.getElementById(`${field.id}-error`).textContent = errors[field.id] || ''
    }
    if (errors.email) email.focus()
    else if (errors.password) password.focus()
  }

  toggle.addEventListener('click', () => {
    const show = password.type === 'password'
    password.type = show ? 'text' : 'password'
    toggle.textContent = show ? 'Hide' : 'Show'
    toggle.setAttribute('aria-label', show ? 'Hide password' : 'Show password')
    toggle.setAttribute('aria-pressed', String(show))
  })

  form.addEventListener('submit', async event => {
    event.preventDefault()
    if (busy || event.isComposing) return
    const submittedEmail = email.value.trim()
    const errors = validateLogin(submittedEmail, password.value)
    showErrors(errors)
    if (Object.keys(errors).length) {
      renderFeedback(document, 'Check the highlighted fields.')
      return
    }
    busy = true
    button.disabled = true
    form.setAttribute('aria-busy', 'true')
    renderFeedback(document, 'Logging in…')
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 10000)
    try {
      const response = await fetchRequest('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ email: submittedEmail, password: password.value }),
        signal: controller.signal
      })
      const result = await response.json()
      showErrors(result.errors || {})
      renderFeedback(document, result.message, submittedEmail)
      if (response.ok) password.value = ''
    } catch {
      renderFeedback(document, 'Cannot reach the server. Check your connection and try again.', submittedEmail)
    } finally {
      clearTimeout(timeout)
      busy = false
      button.disabled = false
      form.setAttribute('aria-busy', 'false')
    }
  })
}

if (typeof document !== 'undefined') setupLogin(document)
