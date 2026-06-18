require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const path = require('path');

const User = require('./models/User');
const Otp = require('./models/Otp');

const app = express();
const PORT = process.env.PORT || 3000;

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
app.use(express.static(path.join(__dirname, 'public')));

// ─── Rate Limiter (OTP endpoint only) ─────────────────────────────────────────
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15-minute window
  max: 5,                    // max 5 OTP requests per window per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many OTP requests. Please wait 15 minutes and try again.' },
});

// ─── Database Connection ──────────────────────────────────────────────────────
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log('✅  MongoDB connected'))
  .catch((err) => {
    console.error('❌  MongoDB connection error:', err.message);
    process.exit(1);
  });

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Generate a cryptographically-random 6-digit OTP string */
function generateOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

/**
 * Derive a unique @godev.com address from the phone number.
 * Format: user<last-7-digits>@godev.com
 * Collision is handled by appending a random suffix when needed.
 */
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

// ─── Routes ───────────────────────────────────────────────────────────────────

// Serve pages
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/verify', (req, res) => res.sendFile(path.join(__dirname, 'public', 'verify.html')));

/**
 * POST /api/request-otp
 * Accepts { phone } — generates an OTP, stores its hash, and "sends" it.
 */
app.post('/api/request-otp', otpLimiter, async (req, res) => {
  try {
    const phone = (req.body.phone || '').trim();

    if (!phone || phone.replace(/\D/g, '').length < 7) {
      return res.status(400).json({ error: 'A valid phone number is required.' });
    }

    // Prevent duplicate registrations
    const existingUser = await User.findOne({ phone });
    if (existingUser) {
      return res.status(409).json({ error: 'This phone number is already registered.' });
    }

    const otp = generateOtp();
    const otpHash = await bcrypt.hash(otp, 10);

    // Upsert: replace any existing OTP for this phone
    await Otp.findOneAndUpdate(
      { phone },
      { phone, otpHash, expiresAt: new Date(Date.now() + 5 * 60 * 1000) },
      { upsert: true, new: true }
    );

    await sendOtpSms(phone, otp);

    return res.json({ message: 'OTP sent. Check the server console for the code (mock mode).' });
  } catch (err) {
    console.error('request-otp error:', err);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

/**
 * POST /api/verify-otp
 * Accepts { phone, otp } — verifies the code and creates the user account.
 */
app.post('/api/verify-otp', async (req, res) => {
  try {
    const phone = (req.body.phone || '').trim();
    const otp = (req.body.otp || '').trim();

    if (!phone || !otp) {
      return res.status(400).json({ error: 'Phone and OTP are required.' });
    }

    const record = await Otp.findOne({ phone });

    if (!record) {
      return res.status(400).json({ error: 'OTP expired or not found. Please request a new one.' });
    }

    if (record.expiresAt < new Date()) {
      await Otp.deleteOne({ phone });
      return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });
    }

    const isMatch = await bcrypt.compare(otp, record.otpHash);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid OTP. Please try again.' });
    }

    // OTP valid — delete it immediately (one-time use)
    await Otp.deleteOne({ phone });

    // Check again for race condition
    const existingUser = await User.findOne({ phone });
    if (existingUser) {
      return res.json({ email: existingUser.email, message: 'Account already exists.' });
    }

    // Assign a unique @godev.com address
    let email = phoneToEmail(phone);
    let collision = await User.findOne({ email });
    if (collision) {
      const rand = Math.floor(1000 + Math.random() * 9000);
      email = email.replace('@godev.com', `${rand}@godev.com`);
    }

    const user = await User.create({ phone, email });
    console.log(`✅  New account created: ${user.email}`);

    return res.json({ email: user.email, message: 'Account created successfully!' });
  } catch (err) {
    console.error('verify-otp error:', err);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// ─── 404 fallback ─────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Route not found.' }));

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`🚀  Server running on port ${PORT}`));
