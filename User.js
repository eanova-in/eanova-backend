const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String },
  firm: { type: String },
  email: { type: String, required: true, unique: true },
  // Google দিয়ে সাইন-ইন করা একাউন্টের কোনো password থাকে না (Google-ই
  // ইমেইল ভেরিফাই করে দেয়, তাই দরকারও নেই) — তাই password এখন শুধু
  // তখনই required, যখন googleId সেট করা নেই। সাধারণ email/OTP signup-এর
  // জন্য আগের মতোই password বাধ্যতামূলক থাকছে, কিছুই বদলায়নি সেখানে।
  password: { type: String, required: function () { return !this.googleId; } },
  googleId: { type: String, default: null },
  region: { type: String, default: 'in' },

  // Subscription — all three of these are set together whenever a plan is
  // purchased (see /api/update-profile). Missing any one of them was the
  // original bug: the frontend was sending activePlan and
  // subscriptionExpiry, but the old schema only had subscriptionActive, so
  // Mongoose silently dropped the other two fields on save. A device that
  // then re-fetched /api/user-data got subscriptionActive back but no plan
  // name/expiry, so the dashboard showed "no plan" even though the purchase
  // had gone through.
  subscriptionActive: { type: Boolean, default: false },
  activePlan: { type: String, default: null },       // 'first' | 'monthly' | 'annual'
  subscriptionExpiry: { type: Number, default: null }, // ms epoch timestamp
  hasPaidBefore: { type: Boolean, default: false },

  profilePic: { type: String, default: '' }, // data URL, so cross-device profile photo works

  // Free-trial daily reconciliation cap: one match per calendar day.
  // Stored as an ISO date string ('YYYY-MM-DD') for the last day a
  // reconciliation was run, so it resets naturally at midnight without a cron job.
  lastReconciliationDate: { type: String, default: null },

  clients: { type: Array, default: [] },

  // Referral program. referralCode is this user's own shareable code
  // (assigned once, at account creation, for every account — random and
  // non-sequential so codes can't be guessed/enumerated). referredBy is
  // the code THEY signed up with, if any — set once at creation and never
  // changed afterward, so it can't be gamed by editing it post-signup.
  referralCode: { type: String, unique: true, sparse: true, index: true },
  referredBy: { type: String, default: null },
  // Set when the user clicks "Request Withdrawal" while eligible (balance
  // >= ₹100) — just a marker so the founder can find pending requests;
  // actual payout is manual (see the withdraw-request route's response).
  referralWithdrawalRequestedAt: { type: Number, default: null }
});

module.exports = mongoose.model('User', userSchema);
