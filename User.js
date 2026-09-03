const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String },
  firm: { type: String },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
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

  // The receipt for the most recent purchase — stored server-side (not just
  // in the browser's localStorage) so "Download Receipt" still works after
  // logging in on a different device, or after a session had to be renewed.
  // Set together with subscriptionActive/activePlan/subscriptionExpiry in
  // /api/update-profile whenever a plan purchase goes through.
  lastReceipt: {
    type: {
      txnId: String,
      plan: String,
      amount: String,
      method: String,
      name: String,
      email: String,
      date: Number,   // ms epoch timestamp of purchase
      expiry: Number  // ms epoch timestamp — matches subscriptionExpiry at time of purchase
    },
    default: null
  },

  profilePic: { type: String, default: '' }, // data URL, so cross-device profile photo works

  // Free-trial daily reconciliation cap: one match per calendar day, only
  // while the 14-day trial window is running and no paid plan is active.
  // Stored as an ISO date string ('YYYY-MM-DD') for the last day a
  // reconciliation was run, so it resets naturally at midnight without a cron job.
  lastReconciliationDate: { type: String, default: null },

  // When the account's 14-day free trial started. Set once, at signup, and
  // never touched again. Existing accounts created before this field existed
  // don't have it — the backend treats a missing value as "trial starts now"
  // (see /api/user-data and /api/login), so no one already using the app
  // loses trial access because of this upgrade.
  accountCreatedAt: { type: Number, default: null },

  clients: { type: Array, default: [] }
});

module.exports = mongoose.model('User', userSchema);
