const mongoose = require('mongoose');

const importedMessageSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  source:    { type: String, default: 'gmail' },
  gmailId:   { type: String, required: true },
  gmailFrom: { type: String, default: '' },
  gmailTo:   { type: String, default: '' },
  subject:   { type: String, default: '(no subject)' },
  body:      { type: String, default: '' },
  snippet:   { type: String, default: '' },
  date:      { type: Date, default: Date.now },
  read:      { type: Boolean, default: false },
  starred:   { type: Boolean, default: false },
});

importedMessageSchema.index({ userId: 1, gmailId: 1 }, { unique: true });
importedMessageSchema.index({ userId: 1, date: -1 });

module.exports = mongoose.model('ImportedMessage', importedMessageSchema);
