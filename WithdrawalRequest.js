const mongoose = require('mongoose');

// A manual-fulfillment queue, not an automated payout system — there's no
// admin panel yet, so the founder checks this collection directly (or a
// simple query) and pays out via bank transfer/UPI, then marks it done.
// Kept separate from ReferralCommission so "requested a withdrawal" and
// "which specific commissions were cashed out" can be reasoned about
// independently.
const withdrawalRequestSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  userEmail: { type: String, required: true },
  userName: { type: String, default: '' },
  amount: { type: Number, required: true },
  requestedAt: { type: Number, required: true }, // ms epoch
  status: { type: String, enum: ['pending', 'completed'], default: 'pending' },
  completedAt: { type: Number, default: null }
});

module.exports = mongoose.model('WithdrawalRequest', withdrawalRequestSchema);
