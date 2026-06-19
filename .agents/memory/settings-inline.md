---
name: Settings inline panel
description: Why settings must be embedded in the mail SPA rather than a separate /settings page
---

## Rule
Settings UI must render as an inline panel inside mail.html, not as a separate `/settings` page.

**Why:** When mail.html API calls return 401, the code calls `window.location.href = '/login'` which clears the token before navigating. If the user then uses browser back to return to /mail, the UI is cached (JS doesn't re-run) so it looks logged in — but the token is gone. Clicking Settings then navigates to `/settings`, which reads the now-missing token, and immediately redirects to login. Users experience this as "Settings doesn't let me in."

**How to apply:** The `openSettings()` function in mail.html renders the full settings panel inside `#content-panel` by hiding the list panel and injecting HTML + event handlers. All settings API calls use the same `api()` helper as the rest of the mail SPA, so auth is consistent.
