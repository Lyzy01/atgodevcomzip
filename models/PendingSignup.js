const mongoose = require('mongoose');

const pendingSignupSchema = new mongoose.Schema({
  phone:        { type: String, required: true, unique: true },
  username:     { type: String, required: true },
  email:        { type: String, required: true },
  passwordHash: { type: String, required: true },
  expiresAt:    { type: Date, default: () => new Date(Date.now() + 10 * 60 * 1000) },
});

pendingSignupSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('PendingSignup', pendingSignupSchema);
