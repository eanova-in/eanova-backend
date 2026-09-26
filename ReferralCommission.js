const mongoose = require('mongoose');

// One row per successful, commission-earning purchase made by someone who
// signed up through another user's referral link. Kept as its own ledger
// (not just a running balance number on User) because each commission
// needs its own 7-day unlock date and must be independently reversible if
// the underlying purchase is refunded within that window — a single
// running total couldn't support either of those.
const referralCommissionSchema = new mongoose.Schema({
  referrerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  referredUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  referredUserName: { type: String, default: '' },
  referredUserEmail: { type: String, default: '' },
  plan: { type: String, required: true },
  baseAmount: { type: Number, required: true },       // pre-charges plan price the 8% is computed from
  commissionAmount: { type: Number, required: true }, // 8% of baseAmount

  // One commission per Razorpay payment, ever — the unique index here is
  // what makes crediting idempotent (if /api/razorpay/verify-payment were
  // ever somehow called twice for the same payment, the second insert
  // simply fails instead of double-crediting).
  razorpayPaymentId: { type: String, required: true, unique: true },

  creditedAt: { type: Number, required: true }, // ms epoch
  unlocksAt: { type: Number, required: true },  // creditedAt + 7 days — withdrawable only once now >= this

  // 'active'    — normal state; counts toward balance, locked or unlocked
  //               depending on unlocksAt vs. now (checked at read time,
  //               no cron job needed — same pattern as the trial's daily
  //               reconciliation-date reset elsewhere in this app).
  // 'reversed'  — the underlying payment was refunded within the 7-day
  //               window; no longer counts toward any balance.
  // 'withdrawn' — already paid out to the referrer; counts toward
  //               lifetime earnings but not current withdrawable balance.
  status: { type: String, enum: ['active', 'reversed', 'withdrawn'], default: 'active' }
});

module.exports = mongoose.model('ReferralCommission', referralCommissionSchema);
