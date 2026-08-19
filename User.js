const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String },
  firm: { type: String },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  region: { type: String, default: 'in' },
  subscriptionActive: { type: Boolean, default: false },
  clients: { type: Array, default: [] }
});

module.exports = mongoose.model('User', userSchema);