const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  from: { type: String, required: true, lowercase: true, trim: true },
  to:   { type: String, required: true, lowercase: true, trim: true },
  subject: { type: String, default: '(no subject)', trim: true },
  body:    { type: String, default: '' },
  read:    { type: Boolean, default: false },
  trashedByRecipient: { type: Boolean, default: false },
  trashedBySender:    { type: Boolean, default: false },
  sentAt: { type: Date, default: Date.now },
});

messageSchema.index({ to: 1, sentAt: -1 });
messageSchema.index({ from: 1, sentAt: -1 });

module.exports = mongoose.model('Message', messageSchema);
