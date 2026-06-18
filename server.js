require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const { MongoStore } = require('connect-mongo');
const path = require('path');

const User = require('./models/User');
const Otp  = require('./models/Otp');

const app = express();
const PORT      = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

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

// ─── Sessions ─────────────────────────────────────────────────────────────────
app.use(session({
  secret: process.env.SESSION_SECRET || 'godev-fallback-secret',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: MONGO_URI }),
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000, httpOnly: true, sameSite: 'lax' },
}));

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

// ─── Auth middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated.' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated.' });
  if (req.session.role !== 'admin') return res.status(403).json({ error: 'Admin access required.' });
  next();
}

// ─── Database ─────────────────────────────────────────────────────────────────
mongoose.connect(MONGO_URI)
  .then(async () => {
    console.log('✅  MongoDB connected');
    await seedAdmin();
  })
  .catch(err => { console.error('❌  MongoDB connection error:', err.message); process.exit(1); });

// ─── Seed admin ───────────────────────────────────────────────────────────────
async function seedAdmin() {
  const adminEmail = 'kimlyrainmendez@godev.com';
  const adminPass  = 'GoDev@Admin2026';

  const existing = await User.findOne({ email: adminEmail });
  if (!existing) {
    const passwordHash = await bcrypt.hash(adminPass, 12);
    await User.create({
      username: 'kimlyrainmendez',
      email:    adminEmail,
      phone:    '+10000000001',
      passwordHash,
      role:     'admin',
    });
    console.log(`✅  Admin seeded: ${adminEmail}`);
    console.log(`🔑  Admin password: ${adminPass}  (change this after first login)`);
  } else if (!existing.passwordHash) {
    // Migrate old admin that has no password yet
    existing.passwordHash = await bcrypt.hash(adminPass, 12);
    existing.username = existing.username || 'kimlyrainmendez';
    await existing.save();
    console.log(`🔄  Admin migrated with password. Password: ${adminPass}`);
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function generateOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

/**
 * TODO: SMS Integration
 * ──────────────────────────────────────────────────────────────────────────────
 * Replace console.log with your Twilio call:
 *   const client = require('twilio')(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
 *   await client.messages.create({ body: `Your code: ${otp}`, from: process.env.TWILIO_PHONE_NUMBER, to: phone });
 * ──────────────────────────────────────────────────────────────────────────────
 */
async function sendOtpSms(phone, otp) {
  console.log(`\n📲  [MOCK SMS] OTP for ${phone}: ${otp}\n`);
}

// ─── Pages ────────────────────────────────────────────────────────────────────
app.get('/',            (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/verify',      (req, res) => res.sendFile(path.join(__dirname, 'public', 'verify.html')));
app.get('/login',       (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/dashboard',   (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/admin',       (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// ─── Check username availability ──────────────────────────────────────────────
app.get('/api/check-username', async (req, res) => {
  try {
    const username = (req.query.username || '').trim().toLowerCase();
    if (!username || !/^[a-z0-9._-]{3,30}$/.test(username))
      return res.status(400).json({ available: false, error: 'Invalid username format.' });

    const exists = await User.findOne({ username });
    return res.json({ available: !exists });
  } catch (err) {
    return res.status(500).json({ available: false });
  }
});

// ─── Signup: validate + send OTP ─────────────────────────────────────────────
app.post('/api/signup', otpLimiter, async (req, res) => {
  try {
    const username = (req.body.username || '').trim().toLowerCase();
    const password = (req.body.password || '');
    const phone    = (req.body.phone    || '').trim();

    // Validate
    if (!username || !/^[a-z0-9._-]{3,30}$/.test(username))
      return res.status(400).json({ error: 'Invalid username format.' });
    if (password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    if (!phone || phone.replace(/\D/g, '').length < 7)
      return res.status(400).json({ error: 'A valid phone number is required.' });

    // Check uniqueness
    const emailToCheck = `${username}@godev.com`;
    if (await User.findOne({ username }))
      return res.status(409).json({ error: `"${username}" is already taken.` });
    if (await User.findOne({ phone }))
      return res.status(409).json({ error: 'This phone number is already registered.' });

    // Store pending signup in session (created after OTP)
    const passwordHash = await bcrypt.hash(password, 12);
    req.session.pendingSignup = { username, email: emailToCheck, phone, passwordHash };

    // Generate + store OTP
    const otp     = generateOtp();
    const otpHash = await bcrypt.hash(otp, 10);
    await Otp.findOneAndUpdate(
      { phone },
      { phone, otpHash, expiresAt: new Date(Date.now() + 5 * 60 * 1000) },
      { upsert: true, new: true }
    );

    await sendOtpSms(phone, otp);
    return res.json({ message: 'OTP sent.' });
  } catch (err) {
    console.error('signup error:', err);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// ─── Signup: verify OTP + create account ─────────────────────────────────────
app.post('/api/verify-otp', async (req, res) => {
  try {
    const otp = (req.body.otp || '').trim();
    if (!otp) return res.status(400).json({ error: 'OTP is required.' });

    const pending = req.session.pendingSignup;
    if (!pending) return res.status(400).json({ error: 'No pending signup. Please start over.' });

    const record = await Otp.findOne({ phone: pending.phone });
    if (!record || record.expiresAt < new Date()) {
      await Otp.deleteOne({ phone: pending.phone });
      return res.status(400).json({ error: 'OTP expired. Please start over.' });
    }

    const isMatch = await bcrypt.compare(otp, record.otpHash);
    if (!isMatch) return res.status(400).json({ error: 'Invalid code. Please try again.' });

    await Otp.deleteOne({ phone: pending.phone });

    // Create user
    const user = await User.create({
      username:     pending.username,
      email:        pending.email,
      phone:        pending.phone,
      passwordHash: pending.passwordHash,
      role:         'user',
    });
    console.log(`✅  New account: ${user.email}`);

    // Clear pending, create session
    delete req.session.pendingSignup;
    req.session.userId = user._id.toString();
    req.session.role   = user.role;

    return res.json({ email: user.email, role: user.role, message: 'Account created!' });
  } catch (err) {
    console.error('verify-otp error:', err);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// ─── Login: email + password ──────────────────────────────────────────────────
app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const email    = (req.body.email    || '').trim().toLowerCase();
    const password = (req.body.password || '');

    if (!email || !password)
      return res.status(400).json({ error: 'Email and password are required.' });

    const user = await User.findOne({ email });
    if (!user)
      return res.status(401).json({ error: 'Invalid email or password.' });

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch)
      return res.status(401).json({ error: 'Invalid email or password.' });

    req.session.userId = user._id.toString();
    req.session.role   = user.role;

    return res.json({ email: user.email, role: user.role, message: 'Signed in!' });
  } catch (err) {
    console.error('login error:', err);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// ─── Me ───────────────────────────────────────────────────────────────────────
app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId).select('-passwordHash -__v');
    if (!user) return res.status(404).json({ error: 'User not found.' });
    return res.json(user);
  } catch { return res.status(500).json({ error: 'Server error.' }); }
});

// ─── Logout ───────────────────────────────────────────────────────────────────
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ message: 'Signed out.' });
  });
});

// ─── Admin: list users ────────────────────────────────────────────────────────
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-passwordHash -__v').sort({ createdAt: -1 });
    return res.json({ users });
  } catch { return res.status(500).json({ error: 'Server error.' }); }
});

// ─── Admin: delete user ───────────────────────────────────────────────────────
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
