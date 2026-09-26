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

  // ------------------------------------------------------------------
  // Share & Earn (referral) — added [date TBD].
  // referralCode: this user's own unique code, given out in their
  // referral link (eanova.in/?ref=CODE). Generated once at signup and
  // never reused, so it can double as a lookup key.
  // referredBy: the referralCode of whoever referred *this* user, if
  // any — set once at signup, never changed afterwards.
  // pointsLedger: append-only history of referral commission earned by
  // this user. Each entry is 8% of a referred account's plan purchase,
  // held for 7 days (availableAt) before it can be withdrawn, to cover
  // the refund window. status moves active -> withdrawn (once a
  // withdrawal request is made) or active -> reversed (if the referred
  // purchase was refunded within the 7-day window; set manually by the
  // founder via /api/admin/mark-refunded when a Razorpay refund is
  // processed, since refunds themselves are handled manually outside
  // this app).
  // withdrawalRequests: log of "please pay me" requests — the actual
  // payout (UPI/bank transfer) happens manually outside the app after
  // the user confirms details over Live Chat or email, so this is a
  // record, not a payment integration.
  // ------------------------------------------------------------------
  referralCode: { type: String, default: null, unique: true, sparse: true },
  referredBy: { type: String, default: null },
  pointsLedger: { type: Array, default: [] },
  withdrawalRequests: { type: Array, default: [] }
});

module.exports = mongoose.model('User', userSchema);
