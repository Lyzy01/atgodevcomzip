# GoDev Mail

A self-hosted email client where users sign up and get a free `@godev.com` email address. Built with Node.js, Express, MongoDB, and JWT auth.

## Features
- Sign up and claim a `yourname@godev.com` address
- Inbox, Sent, Trash, Starred folders
- Compose and send messages between @godev.com users
- Optional Gmail sync (connect a real Gmail account to view those emails here too)
- Admin panel to manage users

## How to run
```
node server.js
```
The server starts on port 5000 (or `PORT` env var).

## Required secrets
- `MONGO_URI` — MongoDB connection string (e.g. from MongoDB Atlas)
- `SESSION_SECRET` — JWT signing secret (already configured)

## Optional secrets (for Gmail sync)
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_REDIRECT_URI` — set to `https://<your-domain>/auth/google/callback`

## Stack
- **Backend:** Node.js, Express, Mongoose (MongoDB)
- **Auth:** JWT stored in localStorage as `godev_token`
- **Frontend:** Vanilla HTML/CSS/JS in `public/`
- **Models:** `User`, `Message`, `Otp`, `PendingSignup`, `ImportedMessage` in `models/`

## User preferences
