export function validateLogin (email, password) {
  const errors = {}
  if (typeof email !== 'string' || !email.trim()) {
    errors.email = 'Enter your email.'
  } else if (!email.trim().includes('@') || email.trim().length > 254) {
    errors.email = 'Use an email containing @ and at most 254 characters.'
  }
  if (typeof password !== 'string' || !password) {
    errors.password = 'Enter your password.'
  } else if (password.length < 8) {
    errors.password = 'Use at least 8 characters.'
  } else if (new TextEncoder().encode(password).length > 72) {
    errors.password = 'Use at most 72 bytes for this bcrypt demonstration.'
  }
  return errors
}
