// ============================================================
// EANOVA — ADMIN PANEL BACKEND (শুধু founder-এর জন্য)
//
// server.js থেকে এভাবে চালু হয় (fallback 404 রুটের ঠিক আগে):
//     require('./admin')(app, { User, summarizePoints });
//
// দরকারি Environment Variables (Render → Environment):
//     ADMIN_USERNAME   — আপনার বেছে নেওয়া ইউজারনেম
//     ADMIN_PASSWORD   — আপনার বেছে নেওয়া পাসওয়ার্ড (লম্বা ও কঠিন রাখুন)
// এই দুটো সেট না থাকলে admin রুটগুলো নিরাপদে সবসময় বন্ধ থাকবে।
//
// সিকিউরিটি:
//  - Admin টোকেন আলাদা secret (JWT_SECRET + ':admin') দিয়ে সই হয়, তাই
//    সাধারণ ইউজারের টোকেন দিয়ে admin রুট খোলা যায় না, আবার admin টোকেন
//    দিয়েও কোনো সাধারণ ইউজার-রুট (requireAuth) খোলা যায় না।
//  - লগইনে আলাদা কড়া rate-limit (১৫ মিনিটে ১০ বার)।
//  - টোকেনের মেয়াদ ২ ঘন্টা।
//  - পাসওয়ার্ড/hash/ক্লায়েন্ট ডেটা/প্রোফাইল ছবি কখনো রেসপন্সে যায় না।
// ============================================================
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');

module.exports = function mountAdmin(app, deps) {
  const User = deps.User;
  const summarizePoints = deps.summarizePoints;
  const ADMIN_JWT_SECRET = process.env.JWT_SECRET + ':admin';

  const r2 = function (n) { return Math.round(n * 100) / 100; };
  const sha = function (s) { return crypto.createHash('sha256').update(String(s)).digest(); };
  const safeEqual = function (a, b) { return crypto.timingSafeEqual(sha(a), sha(b)); };
  const noStore = function (res) { res.set('Cache-Control', 'no-store, private'); };

  const adminLoginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: 'Too many admin login attempts. Try again after 15 minutes.' }
  });

  function requireAdmin(req, res, next) {
    try {
      const h = req.headers.authorization || '';
      const token = h.startsWith('Bearer ') ? h.slice(7) : null;
      if (!token) return res.status(401).json({ message: 'Not authenticated' });
      const decoded = jwt.verify(token, ADMIN_JWT_SECRET);
      if (decoded.role !== 'admin') return res.status(401).json({ message: 'Not authenticated' });
      next();
    } catch (e) {
      return res.status(401).json({ message: 'Session expired. Please log in again.' });
    }
  }

  // ledger entry-র বর্তমান অবস্থা (summarizePoints-এর লজিকের সাথে হুবহু মেলানো)
  function entryStatus(e, now) {
    if (e.status === 'reversed') return 'reversed';
    if (e.status === 'withdrawn') return 'withdrawn';
    return now >= e.availableAt ? 'available' : 'on_hold';
  }

  // ------------------------------------------------------------
  // POST /api/admin/login
  // ------------------------------------------------------------
  app.post('/api/admin/login', adminLoginLimiter, async (req, res) => {
    try {
      if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD) {
        return res.status(500).json({ message: 'Admin panel is not configured on the server yet (set ADMIN_USERNAME and ADMIN_PASSWORD).' });
      }
      const body = req.body || {};
      const okUser = safeEqual(body.username || '', process.env.ADMIN_USERNAME);
      const okPass = safeEqual(body.password || '', process.env.ADMIN_PASSWORD);
      if (!(okUser && okPass)) {
        await new Promise(function (r) { setTimeout(r, 600); }); // brute-force ধীর করতে
        return res.status(401).json({ message: 'Wrong username or password' });
      }
      const token = jwt.sign({ role: 'admin' }, ADMIN_JWT_SECRET, { expiresIn: '2h' });
      noStore(res);
      res.json({ token: token, expiresInSeconds: 2 * 60 * 60 });
    } catch (err) {
      console.error('Admin login error:', err.message || err);
      res.status(500).json({ message: 'Server error' });
    }
  });

  // ------------------------------------------------------------
  // GET /api/admin/users — সব ইউজার, পুরনো → নতুন (নিচে নতুন)
  // সাইনআপের সময় আসে প্রতিটা ডকুমেন্টের _id-র ভেতরের timestamp থেকে।
  // ------------------------------------------------------------
  app.get('/api/admin/users', requireAdmin, async (req, res) => {
    try {
      noStore(res);
      const now = Date.now();
      const docs = await User.find({})
        .select('_id name firm email region googleId subscriptionActive activePlan subscriptionExpiry hasPaidBefore referralCode referredBy pointsLedger')
        .sort({ _id: 1 })
        .lean();

      const referredCount = {};
      const boughtCount = {};
      docs.forEach(function (u) {
        if (u.referredBy) {
          referredCount[u.referredBy] = (referredCount[u.referredBy] || 0) + 1;
          if (u.hasPaidBefore) boughtCount[u.referredBy] = (boughtCount[u.referredBy] || 0) + 1;
        }
      });

      const users = docs.map(function (u, i) {
        const planActive = !!(u.subscriptionActive && u.subscriptionExpiry && u.subscriptionExpiry > now);
        return {
          serial: i + 1,
          id: String(u._id),
          name: u.name || '',
          firm: u.firm || '',
          email: u.email,
          signedUpAt: new mongoose.Types.ObjectId(String(u._id)).getTimestamp().toISOString(),
          planActive: planActive,
          activePlan: u.activePlan || null,
          subscriptionExpiry: u.subscriptionExpiry || null,
          hasPaidBefore: !!u.hasPaidBefore,
          referredCount: u.referralCode ? (referredCount[u.referralCode] || 0) : 0,
          boughtCount: u.referralCode ? (boughtCount[u.referralCode] || 0) : 0,
          availableBalance: summarizePoints(u).availableBalance
        };
      });

      res.json({
        asOf: new Date(now).toISOString(),
        total: users.length,
        paidActive: users.filter(function (u) { return u.planActive; }).length,
        users: users
      });
    } catch (err) {
      console.error('Admin list users error:', err.message || err);
      res.status(500).json({ message: 'Server error' });
    }
  });

  // ------------------------------------------------------------
  // GET /api/admin/users/:id — একজনের পুরো বিস্তারিত
  // ------------------------------------------------------------
  app.get('/api/admin/users/:id', requireAdmin, async (req, res) => {
    try {
      noStore(res);
      if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
        return res.status(400).json({ message: 'Invalid user id' });
      }
      const u = await User.findById(req.params.id)
        .select('-password -profilePic')
        .lean();
      if (!u) return res.status(404).json({ message: 'User not found' });

      const now = Date.now();
      const points = summarizePoints(u);
      const ledgerRaw = u.pointsLedger || [];

      // কার কাছ থেকে কত আয় (reverse হওয়া এন্ট্রি ও admin adjustment বাদে)
      const earnedFrom = {};
      ledgerRaw.forEach(function (e) {
        if (e.type === 'earn' && !e.adminAdjusted && e.status !== 'reversed') {
          earnedFrom[e.buyerEmail] = r2((earnedFrom[e.buyerEmail] || 0) + e.amount);
        }
      });

      let referred = [];
      if (u.referralCode) {
        const docs = await User.find({ referredBy: u.referralCode })
          .select('_id name email hasPaidBefore')
          .sort({ _id: 1 })
          .lean();
        referred = docs.map(function (d) {
          return {
            id: String(d._id),
            name: d.name || '',
            email: d.email,
            signedUpAt: new mongoose.Types.ObjectId(String(d._id)).getTimestamp().toISOString(),
            bought: !!d.hasPaidBefore,
            earnedFromThem: earnedFrom[d.email] || 0
          };
        });
      }

      let referredBy = null;
      if (u.referredBy) {
        const ref = await User.findOne({ referralCode: u.referredBy }).select('name email').lean();
        referredBy = ref ? { name: ref.name || '', email: ref.email } : { name: '', email: '(account not found)', code: u.referredBy };
      }

      const ledger = ledgerRaw
        .map(function (e) {
          return {
            id: e.id,
            amount: e.amount,
            planPurchased: e.planPurchased || null,
            buyerEmail: e.buyerEmail || '',
            rate: e.rate || 0,
            firstReferralBonus: !!e.firstReferralBonus,
            adminAdjusted: !!e.adminAdjusted,
            note: e.note || '',
            createdAt: e.createdAt,
            availableAt: e.availableAt,
            status: entryStatus(e, now)
          };
        })
        .sort(function (a, b) { return a.createdAt - b.createdAt; });

      res.json({
        id: String(u._id),
        name: u.name || '',
        firm: u.firm || '',
        email: u.email,
        region: u.region || 'in',
        googleLinked: !!u.googleId,
        signedUpAt: new mongoose.Types.ObjectId(String(u._id)).getTimestamp().toISOString(),
        clientsCount: (u.clients || []).length,
        lastReconciliationDate: u.lastReconciliationDate || null,
        plan: {
          active: !!(u.subscriptionActive && u.subscriptionExpiry && u.subscriptionExpiry > now),
          activePlan: u.activePlan || null,
          expiry: u.subscriptionExpiry || null,
          hasPaidBefore: !!u.hasPaidBefore
        },
        referralCode: u.referralCode || null,
        referredBy: referredBy,
        referredCount: referred.length,
        boughtCount: referred.filter(function (r) { return r.bought; }).length,
        referred: referred,
        points: {
          availableBalance: points.availableBalance,
          onHold: points.onHold,
          totalEarned: points.totalEarned,
          withdrawn: points.withdrawn,
          reversed: points.reversed
        },
        ledger: ledger,
        withdrawalRequests: (u.withdrawalRequests || []).slice().sort(function (a, b) { return b.createdAt - a.createdAt; }),
        milestoneClaims: u.milestoneClaims || []
      });
    } catch (err) {
      console.error('Admin user detail error:', err.message || err);
      res.status(500).json({ message: 'Server error' });
    }
  });

  // ------------------------------------------------------------
  // POST /api/admin/users/:id/set-balance { amount, note }
  // "Available balance" ঠিক `amount` করে দেয়। আগের ইতিহাস মোছা হয় না —
  // বদলের পার্থক্যটা একটা admin-adjustment এন্ট্রি হিসেবে ledger-এ জমা
  // হয় (বাড়ালে +, কমালে −), তাই কখন কী বদলেছে সবসময় দেখা যায়।
  // ------------------------------------------------------------
  app.post('/api/admin/users/:id/set-balance', requireAdmin, async (req, res) => {
    try {
      noStore(res);
      if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
        return res.status(400).json({ message: 'Invalid user id' });
      }
      const target = Number((req.body || {}).amount);
      if (!Number.isFinite(target) || target < 0 || target > 10000000) {
        return res.status(400).json({ message: 'Amount must be a number from 0 to 10,000,000.' });
      }
      const note = String((req.body || {}).note || '').slice(0, 200);

      const user = await User.findById(req.params.id);
      if (!user) return res.status(404).json({ message: 'User not found' });

      const before = summarizePoints(user).availableBalance;
      const delta = r2(r2(target) - before);
      if (delta === 0) {
        return res.json({ message: 'Balance is already ₹' + before + ' — nothing changed.', before: before, after: before });
      }

      const now = Date.now();
      user.pointsLedger = user.pointsLedger || [];
      user.pointsLedger.push({
        id: crypto.randomUUID(),
        type: 'earn',
        amount: delta,
        planPurchased: 'admin-adjustment',
        buyerEmail: 'Admin adjustment',
        purchaseRef: 'admin-adjust-' + crypto.randomUUID(),
        rate: 0,
        firstReferralBonus: false,
        adminAdjusted: true,
        note: note,
        createdAt: now,
        availableAt: now,
        status: 'active'
      });
      user.markModified('pointsLedger');
      await user.save();

      const after = summarizePoints(user).availableBalance;
      console.log('[admin] balance for', user.email, 'changed', before, '->', after);
      res.json({ message: 'Available balance changed from ₹' + before + ' to ₹' + after + '.', before: before, after: after });
    } catch (err) {
      console.error('Admin set-balance error:', err.message || err);
      res.status(500).json({ message: 'Server error' });
    }
  });

  // ------------------------------------------------------------
  // POST /api/admin/users/:id/ledger/:entryId/:action   (action = reverse | restore)
  // একটা নির্দিষ্ট কমিশন এন্ট্রি বাতিল (reverse) বা আবার চালু (restore)।
  // ------------------------------------------------------------
  app.post('/api/admin/users/:id/ledger/:entryId/:action', requireAdmin, async (req, res) => {
    try {
      noStore(res);
      const action = req.params.action;
      if (!['reverse', 'restore'].includes(action)) {
        return res.status(400).json({ message: 'Invalid action' });
      }
      if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
        return res.status(400).json({ message: 'Invalid user id' });
      }
      const user = await User.findById(req.params.id);
      if (!user) return res.status(404).json({ message: 'User not found' });

      const entry = (user.pointsLedger || []).find(function (e) { return e.id === req.params.entryId; });
      if (!entry) return res.status(404).json({ message: 'Entry not found' });
      if (entry.adminAdjusted) {
        return res.status(400).json({ message: 'Admin adjustments cannot be reversed — set the balance instead.' });
      }

      if (action === 'reverse') {
        if (entry.status === 'withdrawn') {
          return res.status(400).json({ message: 'This amount is already part of a withdrawal request — it cannot be reversed here.' });
        }
        if (entry.status === 'reversed') return res.json({ message: 'Already reversed.' });
        entry.status = 'reversed';
      } else {
        if (entry.status !== 'reversed') return res.json({ message: 'This entry is not reversed.' });
        entry.status = 'active';
      }
      user.markModified('pointsLedger');
      await user.save();
      res.json({ message: action === 'reverse' ? 'Commission reversed.' : 'Commission restored.' });
    } catch (err) {
      console.error('Admin ledger action error:', err.message || err);
      res.status(500).json({ message: 'Server error' });
    }
  });
};
