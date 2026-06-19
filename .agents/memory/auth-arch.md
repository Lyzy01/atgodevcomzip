---
name: Auth architecture
description: JWT storage, token key, and signup flow for GoDev Mail
---

## JWT Storage
- Token key in localStorage: `godev_token`
- JWT_SECRET: `process.env.SESSION_SECRET || 'godev-jwt-fallback-secret'`
- SESSION_SECRET is NOT set as a Replit secret (only MONGO_URI is), so the fallback is always used — tokens survive server restarts.

## Signup flow
Phone verification was removed. Signup is now: username + password → POST /api/signup → user created directly → JWT returned → redirect to /mail.

**Why removed:** OTP required Twilio (not integrated) so it was mocked with console.log, creating a confusing UX where users were sent to /verify but nothing actually sent.

## Token clearing caution
`localStorage.removeItem('godev_token')` in 401 handlers causes the "settings doesn't let me in" bug. Do not remove the token eagerly — just redirect. The settings panel is now inline in the SPA so this is less of an issue, but be careful with any future page navigations.
