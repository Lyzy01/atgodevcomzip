require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const User          = require('./models/User');
const Otp           = require('./models/Otp');
const Message       = require('./models/Message');
const PendingSignup = require('./models/PendingSignup');

const app = express();
const PORT       = process.env.PORT || 3000;
const MONGO_URI  = process.env.MONGO_URI;
const JWT_SECRET = process.env.SESSION_SECRET || 'godev-jwt-fallback-secret';

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
function generateOtp() { return String(Math.floor(100000 + Math.random() * 900000)); }

/**
 * TODO: SMS Integration — replace console.log with Twilio:
 *   const client = require('twilio')(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
 *   await client.messages.create({ body: `Your code: ${otp}`, from: process.env.TWILIO_PHONE_NUMBER, to: phone });
 */
async function sendOtpSms(phone, otp) {
  console.log(`\n📲  [MOCK SMS] OTP for ${phone}: ${otp}\n`);
}

// ─── Pages ────────────────────────────────────────────────────────────────────
app.get('/',          (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/verify',    (req, res) => res.sendFile(path.join(__dirname, 'public', 'verify.html')));
app.get('/login',     (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/admin',     (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/mail',      (req, res) => res.sendFile(path.join(__dirname, 'public', 'mail.html')));

// ─── Check username ───────────────────────────────────────────────────────────
app.get('/api/check-username', async (req, res) => {
  try {
    const username = (req.query.username || '').trim().toLowerCase();
    if (!username || !/^[a-z0-9._-]{3,30}$/.test(username))
      return res.status(400).json({ available: false, error: 'Invalid username format.' });
    return res.json({ available: !(await User.findOne({ username })) });
  } catch { return res.status(500).json({ available: false }); }
});

// ─── Signup: validate, store pending, send OTP ────────────────────────────────
app.post('/api/signup', otpLimiter, async (req, res) => {
  try {
    const username = (req.body.username || '').trim().toLowerCase();
    const password = (req.body.password || '');
    const phone    = (req.body.phone    || '').trim();

    if (!username || !/^[a-z0-9._-]{3,30}$/.test(username))
      return res.status(400).json({ error: 'Invalid username format.' });
    if (password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    if (!phone || phone.replace(/\D/g, '').length < 7)
      return res.status(400).json({ error: 'A valid phone number is required.' });

    const email = `${username}@godev.com`;
    if (await User.findOne({ username }))
      return res.status(409).json({ error: `"${username}" is already taken.` });
    if (await User.findOne({ phone }))
      return res.status(409).json({ error: 'This phone number is already registered.' });

    const passwordHash = await bcrypt.hash(password, 12);

    // Store pending signup in DB (TTL 10 min)
    await PendingSignup.findOneAndUpdate(
      { phone },
      { phone, username, email, passwordHash, expiresAt: new Date(Date.now() + 10 * 60 * 1000) },
      { upsert: true, new: true }
    );

    const otp = generateOtp();
    await Otp.findOneAndUpdate(
      { phone },
      { phone, otpHash: await bcrypt.hash(otp, 10), expiresAt: new Date(Date.now() + 5 * 60 * 1000) },
      { upsert: true, new: true }
    );

    await sendOtpSms(phone, otp);
    return res.json({ message: 'OTP sent.', phone });
  } catch (err) {
    console.error('signup error:', err);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// ─── Verify OTP → create account → return JWT ────────────────────────────────
app.post('/api/verify-otp', async (req, res) => {
  try {
    const phone = (req.body.phone || '').trim();
    const otp   = (req.body.otp   || '').trim();

    if (!phone || !otp) return res.status(400).json({ error: 'Phone and OTP are required.' });

    const pending = await PendingSignup.findOne({ phone });
    if (!pending || pending.expiresAt < new Date())
      return res.status(400).json({ error: 'Signup session expired. Please start over.' });

    const record = await Otp.findOne({ phone });
    if (!record || record.expiresAt < new Date()) {
      await Otp.deleteOne({ phone });
      return res.status(400).json({ error: 'OTP expired. Please start over.' });
    }
    if (!await bcrypt.compare(otp, record.otpHash))
      return res.status(400).json({ error: 'Invalid code. Please try again.' });

    await Otp.deleteOne({ phone });
    await PendingSignup.deleteOne({ phone });

    const user = await User.create({
      username: pending.username, email: pending.email,
      phone: pending.phone, passwordHash: pending.passwordHash, role: 'user',
    });
    console.log(`✅  New account: ${user.email}`);

    await Message.create({
      from: 'kimlyrainmendez@godev.com', to: user.email,
      subject: `Welcome to GoDev Mail, ${user.username}!`,
      body: `Hi ${user.username},\n\nWelcome to GoDev Mail! Your new email address is:\n\n  ${user.email}\n\nYou can use this inbox to send and receive messages with other @godev.com users.\n\nEnjoy!\n\n— Kimly\nGoDev Mail Administrator`,
    });

    const token = signToken(user);
    return res.json({ token, email: user.email, role: user.role, message: 'Account created!' });
  } catch (err) {
    console.error('verify-otp error:', err);
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

// ─── Logout (client clears token) ────────────────────────────────────────────
app.post('/api/logout', (req, res) => res.json({ message: 'Signed out.' }));

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
