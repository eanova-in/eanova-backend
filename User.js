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

  profilePic: { type: String, default: '' }, // data URL, so cross-device profile photo works

  // Free-trial daily reconciliation cap: one match per calendar day.
  // Stored as an ISO date string ('YYYY-MM-DD') for the last day a
  // reconciliation was run, so it resets naturally at midnight without a cron job.
  lastReconciliationDate: { type: String, default: null },

  clients: { type: Array, default: [] }
});

module.exports = mongoose.model('User', userSchema);
