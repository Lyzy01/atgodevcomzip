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
const Otp = require('./models/Otp');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        scriptSrc: ["'self'", "'unsafe-inline'"],
      },
    },
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── Session ──────────────────────────────────────────────────────────────────
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'godev-fallback-secret',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: MONGO_URI }),
    cookie: {
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      httpOnly: true,
      sameSite: 'lax',
    },
  })
);

app.use(express.static(path.join(__dirname, 'public')));

// ─── Rate Limiter (OTP endpoints) ─────────────────────────────────────────────
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many OTP requests. Please wait 15 minutes and try again.' },
});

// ─── Auth Middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated.' });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated.' });
  if (req.session.role !== 'admin') return res.status(403).json({ error: 'Admin access required.' });
  next();
}

// ─── Database Connection ──────────────────────────────────────────────────────
mongoose
  .connect(MONGO_URI)
  .then(async () => {
    console.log('✅  MongoDB connected');
    await seedAdmin();
  })
  .catch((err) => {
    console.error('❌  MongoDB connection error:', err.message);
    process.exit(1);
  });

// ─── Seed Admin Account ───────────────────────────────────────────────────────
async function seedAdmin() {
  const adminEmail = 'kimlyrainmendez@godev.com';
  const existing = await User.findOne({ email: adminEmail });
  if (!existing) {
    await User.create({
      phone: '+10000000001',
      email: adminEmail,
      role: 'admin',
    });
    console.log(`✅  Admin account seeded: ${adminEmail}`);
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function generateOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function phoneToEmail(phone) {
  const digits = phone.replace(/\D/g, '');
  const suffix = digits.slice(-7);
  return `user${suffix}@godev.com`;
}

/**
 * TODO: SMS Integration
 * ──────────────────────────────────────────────────────────────────────────────
 * Replace the console.log below with your Twilio (or other provider) call.
 *
 * Example Twilio snippet:
 *   const twilio = require('twilio');
 *   const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
 *   await client.messages.create({
 *     body: `Your GoDev verification code is: ${otp}`,
 *     from: process.env.TWILIO_PHONE_NUMBER,
 *     to: phone,
 *   });
 * ──────────────────────────────────────────────────────────────────────────────
 */
async function sendOtpSms(phone, otp) {
  console.log(`\n📲  [MOCK SMS] OTP for ${phone}: ${otp}\n`);
}

// ─── Page Routes ─────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/verify', (req, res) => res.sendFile(path.join(__dirname, 'public', 'verify.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/login-verify', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login-verify.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// ─── Signup: Request OTP ──────────────────────────────────────────────────────
app.post('/api/request-otp', otpLimiter, async (req, res) => {
  try {
    const phone = (req.body.phone || '').trim();
    if (!phone || phone.replace(/\D/g, '').length < 7)
      return res.status(400).json({ error: 'A valid phone number is required.' });

    const existingUser = await User.findOne({ phone });
    if (existingUser)
      return res.status(409).json({ error: 'This phone number is already registered.' });

    const otp = generateOtp();
    const otpHash = await bcrypt.hash(otp, 10);

    await Otp.findOneAndUpdate(
      { phone },
      { phone, otpHash, expiresAt: new Date(Date.now() + 5 * 60 * 1000) },
      { upsert: true, new: true }
    );

    await sendOtpSms(phone, otp);
    return res.json({ message: 'OTP sent.' });
  } catch (err) {
    console.error('request-otp error:', err);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// ─── Signup: Verify OTP & Create Account ──────────────────────────────────────
app.post('/api/verify-otp', async (req, res) => {
  try {
    const phone = (req.body.phone || '').trim();
    const otp = (req.body.otp || '').trim();
    if (!phone || !otp) return res.status(400).json({ error: 'Phone and OTP are required.' });

    const record = await Otp.findOne({ phone });
    if (!record || record.expiresAt < new Date()) {
      await Otp.deleteOne({ phone });
      return res.status(400).json({ error: 'OTP expired or not found. Please request a new one.' });
    }

    const isMatch = await bcrypt.compare(otp, record.otpHash);
    if (!isMatch) return res.status(400).json({ error: 'Invalid OTP. Please try again.' });

    await Otp.deleteOne({ phone });

    let user = await User.findOne({ phone });
    if (!user) {
      let email = phoneToEmail(phone);
      const collision = await User.findOne({ email });
      if (collision) email = email.replace('@godev.com', `${Math.floor(1000 + Math.random() * 9000)}@godev.com`);
      user = await User.create({ phone, email });
      console.log(`✅  New account: ${user.email}`);
    }

    req.session.userId = user._id.toString();
    req.session.role = user.role;

    return res.json({ email: user.email, role: user.role, message: 'Account created!' });
  } catch (err) {
    console.error('verify-otp error:', err);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// ─── Login: Request OTP by Email ─────────────────────────────────────────────
app.post('/api/request-login-otp', otpLimiter, async (req, res) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    if (!email.endsWith('@godev.com'))
      return res.status(400).json({ error: 'Please enter a valid @godev.com email.' });

    const user = await User.findOne({ email });
    if (!user)
      return res.status(404).json({ error: 'No account found with that email address.' });

    // Admin placeholder phone cannot receive SMS — handled separately
    const otp = generateOtp();
    const otpHash = await bcrypt.hash(otp, 10);

    await Otp.findOneAndUpdate(
      { phone: user.phone },
      { phone: user.phone, otpHash, expiresAt: new Date(Date.now() + 5 * 60 * 1000) },
      { upsert: true, new: true }
    );

    await sendOtpSms(user.phone, otp);
    return res.json({ message: 'OTP sent to your registered phone.' });
  } catch (err) {
    console.error('request-login-otp error:', err);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// ─── Login: Verify OTP & Create Session ──────────────────────────────────────
app.post('/api/verify-login-otp', async (req, res) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    const otp = (req.body.otp || '').trim();
    if (!email || !otp) return res.status(400).json({ error: 'Email and OTP are required.' });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'Account not found.' });

    const record = await Otp.findOne({ phone: user.phone });
    if (!record || record.expiresAt < new Date()) {
      await Otp.deleteOne({ phone: user.phone });
      return res.status(400).json({ error: 'OTP expired. Please request a new one.' });
    }

    const isMatch = await bcrypt.compare(otp, record.otpHash);
    if (!isMatch) return res.status(400).json({ error: 'Invalid OTP. Please try again.' });

    await Otp.deleteOne({ phone: user.phone });

    req.session.userId = user._id.toString();
    req.session.role = user.role;

    return res.json({ email: user.email, role: user.role, message: 'Signed in!' });
  } catch (err) {
    console.error('verify-login-otp error:', err);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// ─── Me ───────────────────────────────────────────────────────────────────────
app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId).select('-__v');
    if (!user) return res.status(404).json({ error: 'User not found.' });
    return res.json(user);
  } catch (err) {
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ─── Logout ───────────────────────────────────────────────────────────────────
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ message: 'Signed out.' });
  });
});

// ─── Admin: List Users ────────────────────────────────────────────────────────
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-__v').sort({ createdAt: -1 });
    return res.json({ users });
  } catch (err) {
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ─── Admin: Delete User ───────────────────────────────────────────────────────
app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    if (user.role === 'admin') return res.status(403).json({ error: 'Cannot delete an admin account.' });
    await User.deleteOne({ _id: user._id });
    return res.json({ message: 'User deleted.' });
  } catch (err) {
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ─── 404 ──────────────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Route not found.' }));

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`🚀  Server running on port ${PORT}`));
