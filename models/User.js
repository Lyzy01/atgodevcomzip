const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username:    { type: String, required: true, unique: true, lowercase: true, trim: true },
  email:       { type: String, required: true, unique: true, lowercase: true, trim: true },
  phone:       { type: String, default: '', trim: true },
  passwordHash:{ type: String, required: true },
  role:        { type: String, enum: ['user', 'admin'], default: 'user' },
  displayName: { type: String, default: '' },
  signature:   { type: String, default: '' },
  theme:       { type: String, enum: ['dark', 'light'], default: 'dark' },
  createdAt:   { type: Date, default: Date.now },
});

module.exports = mongoose.model('User', userSchema);
