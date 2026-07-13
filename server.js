require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const { google }       = require('googleapis');
const User             = require('./models/User');
const Otp              = require('./models/Otp');
const Message          = require('./models/Message');
const PendingSignup    = require('./models/PendingSignup');
const ImportedMessage  = require('./models/ImportedMessage');

const app = express();
const PORT       = process.env.PORT || 3000;
const MONGO_URI  = process.env.MONGO_URI;
const JWT_SECRET = process.env.SESSION_SECRET || 'godev-jwt-fallback-secret';

// ─── Google OAuth2 setup ──────────────────────────────────────────────────────
const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID     || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';

function makeOAuth2Client(redirectUri) {
  return new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, redirectUri);
}
function getRedirectUri(req) {
  if (process.env.GOOGLE_REDIRECT_URI) return process.env.GOOGLE_REDIRECT_URI;
  return `https://${req.get('host')}/auth/google/callback`;
}

// ─── Gmail sync function ──────────────────────────────────────────────────────
async function syncGmailMessages(userId, accessToken, refreshToken) {
  const auth = makeOAuth2Client('');
  auth.setCredentials({ access_token: accessToken, refresh_token: refreshToken });
  auth.on('tokens', async (tokens) => {
    if (tokens.access_token) await User.findByIdAndUpdate(userId, { googleAccessToken: tokens.access_token });
  });

  const gmail = google.gmail({ version: 'v1', auth });
  const listRes = await gmail.users.messages.list({ userId: 'me', maxResults: 50, labelIds: ['INBOX'] });
  const msgList = listRes.data.messages || [];

  function extractBody(payload) {
    if (!payload) return '';
    if (payload.body?.data) {
      try { return Buffer.from(payload.body.data, 'base64').toString('utf-8'); } catch { return ''; }
    }
    if (payload.parts) {
      for (const part of payload.parts) {
        if (part.mimeType === 'text/plain') { const t = extractBody(part); if (t) return t; }
      }
      for (const part of payload.parts) { const t = extractBody(part); if (t) return t; }
    }
    return '';
  }

  let synced = 0;
  for (const { id } of msgList) {
    try {
      if (await ImportedMessage.exists({ userId, gmailId: id })) continue;
      const { data: msg } = await gmail.users.messages.get({ userId: 'me', id, format: 'full' });
      const hdrs = {};
      for (const h of msg.payload?.headers || []) hdrs[h.name] = h.value;
      const body = (extractBody(msg.payload) || msg.snippet || '').slice(0, 10000);
      await ImportedMessage.create({
        userId, gmailId: id,
        gmailFrom: hdrs['From'] || '',
        gmailTo:   hdrs['To']   || '',
        subject:   hdrs['Subject'] || '(no subject)',
        body, snippet: msg.snippet || '',
        date:    new Date(parseInt(msg.internalDate)),
        starred: (msg.labelIds || []).includes('STARRED'),
      });
      synced++;
    } catch (e) { console.error(`Gmail import ${id}:`, e.message); }
  }
  await User.findByIdAndUpdate(userId, { googleLastSync: new Date() });
  return synced;
}

app.set('trust proxy', 1);

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc:   ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc:    ["'self'", 'https://fonts.gstatic.com'],
      scriptSrc:  ["'self'", "'unsafe-inline'"],
    },
  },
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── Rate limiters ────────────────────────────────────────────────────────────
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 5, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many OTP requests. Please wait 15 minutes and try again.' },
});
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many login attempts. Please wait 15 minutes.' },
});

// ─── JWT Auth Middleware ──────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not authenticated.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required.' });
    next();
  });
}

function signToken(user) {
  return jwt.sign(
    { userId: user._id.toString(), role: user.role, email: user.email },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// ─── Database ─────────────────────────────────────────────────────────────────
mongoose.connect(MONGO_URI)
  .then(async () => { console.log('✅  MongoDB connected'); await seedAdmin(); })
  .catch(err => { console.error('❌  MongoDB connection error:', err.message); process.exit(1); });

// ─── Seed Admin ───────────────────────────────────────────────────────────────
async function seedAdmin() {
  const adminEmail = 'kimlyrainmendez@godev.com';
  const adminPass  = 'GoDev@Admin2026';
  const existing   = await User.findOne({ email: adminEmail });

  if (!existing) {
    const passwordHash = await bcrypt.hash(adminPass, 12);
    await User.create({ username: 'kimlyrainmendez', email: adminEmail, phone: '+10000000001', passwordHash, role: 'admin' });
    console.log(`✅  Admin seeded: ${adminEmail}`);
    console.log(`🔑  Admin password: ${adminPass}`);
    await Message.create({
      from: 'noreply@godev.com', to: adminEmail,
      subject: 'Welcome to GoDev Mail — Admin Account Ready',
      body: `Hi Kimly,\n\nYour administrator account is ready.\n\nEmail: ${adminEmail}\nRole: Administrator\n\nManage all users from the Admin Panel.\n\n— GoDev Mail Team`,
    });
  } else if (!existing.passwordHash) {
    existing.passwordHash = await bcrypt.hash(adminPass, 12);
    existing.username = existing.username || 'kimlyrainmendez';
    await existing.save();
    console.log(`🔄  Admin migrated. Password: ${adminPass}`);
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// ─── Cookie helper ────────────────────────────────────────────────────────────
function parseCookies(req) {
  const raw = req.headers.cookie || '';
  if (!raw) return {};
  return Object.fromEntries(
    raw.split(';').map(c => {
      const idx = c.indexOf('=');
      if (idx < 0) return [c.trim(), ''];
      return [c.slice(0, idx).trim(), decodeURIComponent(c.slice(idx + 1).trim())];
    })
  );
}

// ─── Pages ────────────────────────────────────────────────────────────────────
app.get('/',          (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/verify',    (req, res) => res.sendFile(path.join(__dirname, 'public', 'verify.html')));
app.get('/login',     (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/mail',      (req, res) => res.sendFile(path.join(__dirname, 'public', 'mail.html')));

// ─── Admin page — server-side auth check ─────────────────────────────────────
app.get('/admin', (req, res) => {
  const cookies = parseCookies(req);
  const token = cookies['godev_auth'];
  if (!token) return res.redirect('/login?next=admin');
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== 'admin') return res.redirect('/mail');
    return res.sendFile(path.join(__dirname, 'public', 'admin.html'));
  } catch {
    res.clearCookie('godev_auth');
    return res.redirect('/login?next=admin');
  }
});

// ─── Check username ───────────────────────────────────────────────────────────
app.get('/api/check-username', async (req, res) => {
  try {
    const username = (req.query.username || '').trim().toLowerCase();
    if (!username || !/^[a-z0-9._-]{3,30}$/.test(username))
      return res.status(400).json({ available: false, error: 'Invalid username format.' });
    return res.json({ available: !(await User.findOne({ username })) });
  } catch { return res.status(500).json({ available: false }); }
});

// ─── Signup → create account directly → return JWT ───────────────────────────
app.post('/api/signup', async (req, res) => {
  try {
    const username = (req.body.username || '').trim().toLowerCase();
    const password = (req.body.password || '');

    if (!username || !/^[a-z0-9._-]{3,30}$/.test(username))
      return res.status(400).json({ error: 'Invalid username format.' });
    if (password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });

    const email = `${username}@godev.com`;
    if (await User.findOne({ username }))
      return res.status(409).json({ error: `"${username}" is already taken.` });

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ username, email, passwordHash, role: 'user' });
    console.log(`✅  New account: ${user.email}`);

    await Message.create({
      from: 'kimlyrainmendez@godev.com', to: user.email,
      subject: `Welcome to GoDev Mail, ${user.username}!`,
      body: `Hi ${user.username},\n\nWelcome to GoDev Mail! Your new email address is:\n\n  ${user.email}\n\nYou can use this inbox to send and receive messages with other @godev.com users.\n\nEnjoy!\n\n— Kimly\nGoDev Mail Administrator`,
    });

    const token = signToken(user);
    res.cookie('godev_auth', token, { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 });
    return res.json({ token, email: user.email, role: user.role, message: 'Account created!' });
  } catch (err) {
    console.error('signup error:', err);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// ─── Login → return JWT ───────────────────────────────────────────────────────
app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const email    = (req.body.email    || '').trim().toLowerCase();
    const password = (req.body.password || '');
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password are required.' });

    const user = await User.findOne({ email });
    if (!user || !await bcrypt.compare(password, user.passwordHash))
      return res.status(401).json({ error: 'Invalid email or password.' });

    const token = signToken(user);
    res.cookie('godev_auth', token, { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 });
    return res.json({ token, email: user.email, role: user.role, message: 'Signed in!' });
  } catch (err) {
    console.error('login error:', err);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// ─── Me ───────────────────────────────────────────────────────────────────────
app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-passwordHash -__v');
    if (!user) return res.status(404).json({ error: 'User not found.' });
    return res.json(user);
  } catch { return res.status(500).json({ error: 'Server error.' }); }
});

// ─── Logout ───────────────────────────────────────────────────────────────────
app.post('/api/logout', (req, res) => {
  res.clearCookie('godev_auth');
  res.json({ message: 'Signed out.' });
});

// ═══════════════════════════════════════════════════════════════════════════════
// MAIL API
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/mail/inbox', requireAuth, async (req, res) => {
  try {
    const messages = await Message.find({ to: req.user.email, trashedByRecipient: false }).sort({ sentAt: -1 }).limit(100);
    return res.json({ messages });
  } catch { return res.status(500).json({ error: 'Server error.' }); }
});

app.get('/api/mail/sent', requireAuth, async (req, res) => {
  try {
    const messages = await Message.find({ from: req.user.email, trashedBySender: false }).sort({ sentAt: -1 }).limit(100);
    return res.json({ messages });
  } catch { return res.status(500).json({ error: 'Server error.' }); }
});

app.get('/api/mail/trash', requireAuth, async (req, res) => {
  try {
    const messages = await Message.find({
      $or: [
        { to: req.user.email, trashedByRecipient: true },
        { from: req.user.email, trashedBySender: true },
      ],
    }).sort({ sentAt: -1 }).limit(100);
    return res.json({ messages });
  } catch { return res.status(500).json({ error: 'Server error.' }); }
});

app.get('/api/mail/starred', requireAuth, async (req, res) => {
  try {
    const messages = await Message.find({
      $or: [{ to: req.user.email }, { from: req.user.email }],
      starred: true,
    }).sort({ sentAt: -1 }).limit(100);
    return res.json({ messages });
  } catch { return res.status(500).json({ error: 'Server error.' }); }
});

app.get('/api/mail/all', requireAuth, async (req, res) => {
  try {
    const messages = await Message.find({
      $or: [
        { to: req.user.email, trashedByRecipient: false },
        { from: req.user.email, trashedBySender: false },
      ],
    }).sort({ sentAt: -1 }).limit(200);
    return res.json({ messages });
  } catch { return res.status(500).json({ error: 'Server error.' }); }
});

app.patch('/api/mail/message/:id/star', requireAuth, async (req, res) => {
  try {
    const msg = await Message.findById(req.params.id);
    if (!msg) return res.status(404).json({ error: 'Message not found.' });
    if (msg.to !== req.user.email && msg.from !== req.user.email)
      return res.status(403).json({ error: 'Access denied.' });
    msg.starred = !msg.starred;
    await msg.save();
    return res.json({ starred: msg.starred });
  } catch { return res.status(500).json({ error: 'Server error.' }); }
});

app.get('/api/mail/unread-count', requireAuth, async (req, res) => {
  try {
    const count = await Message.countDocuments({ to: req.user.email, read: false, trashedByRecipient: false });
    return res.json({ count });
  } catch { return res.status(500).json({ error: 'Server error.' }); }
});

app.post('/api/mail/compose', requireAuth, async (req, res) => {
  try {
    const to      = (req.body.to      || '').trim().toLowerCase();
    const subject = (req.body.subject || '').trim() || '(no subject)';
    const body    = (req.body.body    || '').trim();

    if (!to) return res.status(400).json({ error: 'Recipient is required.' });
    if (!to.endsWith('@godev.com'))
      return res.status(400).json({ error: 'GoDev Mail can only send to @godev.com addresses.' });
    if (to !== 'noreply@godev.com' && !(await User.findOne({ email: to })))
      return res.status(404).json({ error: `No account found for ${to}.` });

    const msg = await Message.create({ from: req.user.email, to, subject, body });
    return res.json({ message: 'Sent!', id: msg._id });
  } catch (err) {
    console.error('compose error:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

app.get('/api/mail/message/:id', requireAuth, async (req, res) => {
  try {
    const msg = await Message.findById(req.params.id);
    if (!msg) return res.status(404).json({ error: 'Message not found.' });
    if (msg.to !== req.user.email && msg.from !== req.user.email)
      return res.status(403).json({ error: 'Access denied.' });
    if (msg.to === req.user.email && !msg.read) { msg.read = true; await msg.save(); }
    return res.json({ message: msg });
  } catch { return res.status(500).json({ error: 'Server error.' }); }
});

app.delete('/api/mail/message/:id', requireAuth, async (req, res) => {
  try {
    const msg = await Message.findById(req.params.id);
    if (!msg) return res.status(404).json({ error: 'Message not found.' });
    if (msg.to === req.user.email)        { msg.trashedByRecipient = true; await msg.save(); }
    else if (msg.from === req.user.email) { msg.trashedBySender    = true; await msg.save(); }
    else return res.status(403).json({ error: 'Access denied.' });
    return res.json({ message: 'Moved to trash.' });
  } catch { return res.status(500).json({ error: 'Server error.' }); }
});

app.delete('/api/mail/message/:id/permanent', requireAuth, async (req, res) => {
  try {
    const msg = await Message.findById(req.params.id);
    if (!msg) return res.status(404).json({ error: 'Message not found.' });
    if (msg.to !== req.user.email && msg.from !== req.user.email)
      return res.status(403).json({ error: 'Access denied.' });
    await Message.deleteOne({ _id: msg._id });
    return res.json({ message: 'Permanently deleted.' });
  } catch { return res.status(500).json({ error: 'Server error.' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// SETTINGS API
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/settings', (req, res) => res.sendFile(path.join(__dirname, 'public', 'settings.html')));

app.get('/api/settings', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('username email phone displayName signature theme createdAt role');
    if (!user) return res.status(404).json({ error: 'User not found.' });
    return res.json({
      user: {
        username:        user.username,
        email:           user.email,
        phone:           user.phone    || '',
        displayName:     user.displayName || '',
        signature:       user.signature   || '',
        theme:           user.theme       || 'dark',
        createdAt:       user.createdAt,
        role:            user.role,
        googleConnected: user.googleConnected || false,
        googleEmail:     user.googleEmail     || '',
        googleLastSync:  user.googleLastSync  || null,
      }
    });
  } catch { return res.status(500).json({ error: 'Server error.' }); }
});

app.patch('/api/settings/profile', requireAuth, async (req, res) => {
  try {
    const { displayName } = req.body;
    if (typeof displayName !== 'string') return res.status(400).json({ error: 'Invalid display name.' });
    const trimmed = displayName.trim().slice(0, 60);
    await User.findByIdAndUpdate(req.user.userId, { displayName: trimmed });
    return res.json({ message: 'Profile updated.' });
  } catch { return res.status(500).json({ error: 'Server error.' }); }
});

app.patch('/api/settings/signature', requireAuth, async (req, res) => {
  try {
    const signature = (req.body.signature || '').slice(0, 1000);
    await User.findByIdAndUpdate(req.user.userId, { signature });
    return res.json({ message: 'Signature saved.' });
  } catch { return res.status(500).json({ error: 'Server error.' }); }
});

app.patch('/api/settings/password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both passwords are required.' });
    if (newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters.' });

    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    if (!await bcrypt.compare(currentPassword, user.passwordHash))
      return res.status(401).json({ error: 'Current password is incorrect.' });

    user.passwordHash = await bcrypt.hash(newPassword, 12);
    await user.save();
    return res.json({ message: 'Password changed successfully.' });
  } catch { return res.status(500).json({ error: 'Server error.' }); }
});

app.patch('/api/settings/theme', requireAuth, async (req, res) => {
  try {
    const { theme } = req.body;
    if (!['dark', 'light'].includes(theme)) return res.status(400).json({ error: 'Invalid theme.' });
    await User.findByIdAndUpdate(req.user.userId, { theme });
    return res.json({ message: 'Theme saved.' });
  } catch { return res.status(500).json({ error: 'Server error.' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// GMAIL OAUTH + SYNC
// ═══════════════════════════════════════════════════════════════════════════════

// Step 1 – redirect user to Google consent screen
app.get('/auth/google', (req, res) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    return res.redirect('/mail?gmailError=not_configured');
  }
  const token = req.query.token || '';
  let userId;
  try { userId = jwt.verify(token, JWT_SECRET).userId; }
  catch { return res.redirect('/login'); }

  const redirectUri = getRedirectUri(req);
  const oauth2 = makeOAuth2Client(redirectUri);
  const url = oauth2.generateAuthUrl({
    access_type: 'offline',
    scope: [
      'https://www.googleapis.com/auth/gmail.readonly',
      'https://www.googleapis.com/auth/userinfo.email',
    ],
    state: Buffer.from(JSON.stringify({ userId, redirectUri })).toString('base64'),
    prompt: 'consent',
  });
  res.redirect(url);
});

// Step 2 – Google redirects back with code
app.get('/auth/google/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error || !code || !state) return res.redirect('/mail?gmailError=cancelled');

  let userId, redirectUri;
  try {
    const parsed = JSON.parse(Buffer.from(state, 'base64').toString('utf-8'));
    userId = parsed.userId; redirectUri = parsed.redirectUri;
  } catch { return res.redirect('/mail?gmailError=invalid_state'); }

  try {
    const oauth2 = makeOAuth2Client(redirectUri);
    const { tokens } = await oauth2.getToken(code);
    oauth2.setCredentials(tokens);

    // Get their Google email
    const oauthService = google.oauth2({ version: 'v2', auth: oauth2 });
    const { data: info } = await oauthService.userinfo.get();

    await User.findByIdAndUpdate(userId, {
      googleConnected:    true,
      googleEmail:        info.email,
      googleAccessToken:  tokens.access_token,
      googleRefreshToken: tokens.refresh_token || undefined,
    });

    // Run initial sync in background (don't await to keep response fast)
    syncGmailMessages(userId, tokens.access_token, tokens.refresh_token).catch(console.error);

    res.redirect('/mail?gmailConnected=1');
  } catch (err) {
    console.error('Google callback error:', err.message);
    res.redirect('/mail?gmailError=auth_failed');
  }
});

// Gmail status
app.get('/api/settings/gmail/status', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('googleConnected googleEmail googleLastSync');
    if (!user) return res.status(404).json({ error: 'User not found.' });
    const count = user.googleConnected
      ? await ImportedMessage.countDocuments({ userId: req.user.userId })
      : 0;
    return res.json({
      connected: user.googleConnected || false,
      email:     user.googleEmail || '',
      lastSync:  user.googleLastSync || null,
      count,
      configured: !!(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET),
    });
  } catch { return res.status(500).json({ error: 'Server error.' }); }
});

// Sync now
app.post('/api/settings/gmail/sync', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('googleConnected googleAccessToken googleRefreshToken');
    if (!user?.googleConnected) return res.status(400).json({ error: 'Gmail not connected.' });
    const synced = await syncGmailMessages(req.user.userId, user.googleAccessToken, user.googleRefreshToken);
    return res.json({ message: `Synced ${synced} new messages.`, synced });
  } catch (err) {
    console.error('Sync error:', err.message);
    return res.status(500).json({ error: 'Sync failed. Your Google token may need to be reconnected.' });
  }
});

// Disconnect
app.delete('/api/settings/gmail/disconnect', requireAuth, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.userId, {
      googleConnected: false, googleEmail: '',
      googleAccessToken: '', googleRefreshToken: '',
    });
    await ImportedMessage.deleteMany({ userId: req.user.userId });
    return res.json({ message: 'Gmail disconnected and messages removed.' });
  } catch { return res.status(500).json({ error: 'Server error.' }); }
});

// Get imported Gmail messages
app.get('/api/mail/gmail', requireAuth, async (req, res) => {
  try {
    const messages = await ImportedMessage.find({ userId: req.user.userId }).sort({ date: -1 }).limit(100);
    return res.json({ messages });
  } catch { return res.status(500).json({ error: 'Server error.' }); }
});

// Get single imported message + mark as read
app.get('/api/mail/gmail/:id', requireAuth, async (req, res) => {
  try {
    const msg = await ImportedMessage.findOne({ _id: req.params.id, userId: req.user.userId });
    if (!msg) return res.status(404).json({ error: 'Message not found.' });
    if (!msg.read) { msg.read = true; await msg.save(); }
    return res.json({ message: msg });
  } catch { return res.status(500).json({ error: 'Server error.' }); }
});

// ─── Admin ────────────────────────────────────────────────────────────────────
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-passwordHash -__v').sort({ createdAt: -1 });
    return res.json({ users });
  } catch { return res.status(500).json({ error: 'Server error.' }); }
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    if (user.role === 'admin') return res.status(403).json({ error: 'Cannot delete an admin account.' });
    await User.deleteOne({ _id: user._id });
    return res.json({ message: 'User deleted.' });
  } catch { return res.status(500).json({ error: 'Server error.' }); }
});

// ─── 404 ──────────────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Route not found.' }));

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`🚀  Server running on port ${PORT}`));
