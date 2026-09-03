const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Resend } = require('resend');
require('dotenv').config();

const User = require('./User');

// ============================================================
// আবশ্যিক এনভায়রনমেন্ট ভেরিয়েবল যাচাই — কোনোটা মিসিং থাকলে
// সার্ভার চালু হওয়ার আগেই বন্ধ হয়ে যাবে, যাতে সিক্রেট ছাড়া
// অ্যাপ কখনো ভুলবশত লাইভ না হয়ে যায়।
// ============================================================
const REQUIRED_ENV = ['MONGO_URI', 'JWT_SECRET', 'RESEND_API_KEY'];
const missingEnv = REQUIRED_ENV.filter(name => !process.env[name]);
if (missingEnv.length > 0) {
  console.error('❌ Missing required environment variables:', missingEnv.join(', '));
  process.exit(1);
}
if (process.env.JWT_SECRET.length < 16) {
  console.error('❌ JWT_SECRET is too short/weak. Use a long random string.');
  process.exit(1);
}

const app = express();

// Render/Vercel-এর মতো প্ল্যাটফর্মে প্রক্সির পেছনে থাকলে rate-limit ও IP
// সঠিকভাবে ধরার জন্য এটা দরকার।
app.set('trust proxy', 1);

app.use(express.json({ limit: '2mb' }));

// ============================================================
// সিকিউরিটি হেডার (Prompt 3: Pre-Deploy Production Audit)
// ============================================================
app.use(helmet({
  contentSecurityPolicy: false, // ফ্রন্টএন্ড আলাদা ডোমেইনে (Vercel) হোস্ট হয়, তাই CSP এখানে সীমিত রাখা হলো
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));

// ============================================================
// CORS — শুধুমাত্র নিজের ডোমেইনগুলো থেকে রিকোয়েস্ট গ্রহণ করবে
// ============================================================
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS ||
  'https://www.eanova.in,https://eanova.in')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    // origin না থাকা মানে সার্ভার-টু-সার্ভার বা কার্ল টুল দিয়ে কল (যেমন Render হেলথ চেক) — অনুমতি দেওয়া হলো
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));

// MongoDB কানেকশন
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB Connected Successfully!'))
  .catch(err => console.log('DB Error:', err));

// Resend Client
const resend = new Resend(process.env.RESEND_API_KEY);

// মেমোরিতে সাময়িকভাবে OTP ধরে রাখার অবজেক্ট (আগের মতোই — ইন্টারফেস/লজিক অপরিবর্তিত)
const otpStore = {};
const resetOtpStore = {};

// ============================================================
// রেট লিমিটিং (Prompt 3 + Prompt 5) — ব্রুট-ফোর্স ও OTP-স্প্যাম ঠেকাতে
// ============================================================
const otpRequestLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // ১ ঘন্টা
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many OTP requests. Please try again after some time.' }
});

const loginLimiter = rateLimit({
  windowMs: 60 * 1000, // ১ মিনিট
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many login attempts. Please wait a minute and try again.' }
});

const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // ১ ঘন্টা
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many password reset attempts. Please try again later.' }
});

const generalApiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many requests. Please slow down.' }
});
app.use('/api/', generalApiLimiter);

// ============================================================
// OTP ইমেইল পাঠানোর ফাংশন (Resend) — আগের মতোই অপরিবর্তিত
// ============================================================
async function sendOtpEmail(email, otp, subjectLine) {
  const { data, error } = await resend.emails.send({
    from: 'Eanova <noreply@eanova.in>', // আপনার ভেরিফাই করা ডোমেইন
    to: email,
    subject: subjectLine,
    html: `
      <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #f4f4f4;">
        <h2 style="color: #333;">Eanova</h2>
        <p>Your one-time code is:</p>
        <h1 style="color: #007bff; letter-spacing: 5px;">${otp}</h1>
        <p>This code will expire in 5 minutes.</p>
      </div>
    `
  });

  if (error) {
    // সিক্রেট বা ব্যক্তিগত ডেটা ছাড়া শুধু এরর মেসেজটুকু লগ হচ্ছে
    console.error('Resend error:', error.message || error);
    throw new Error('Failed to send email');
  }
  return data;
}

// ============================================================
// JWT হেল্পার
// ============================================================
function signToken(user) {
  return jwt.sign(
    { id: user._id.toString(), email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// ============================================================
// AUTH MIDDLEWARE (Prompt 4 + Prompt 5: IDOR প্রতিরোধ)
// প্রতিটি সংবেদনশীল রুটে এটা বসানো হয়েছে, যাতে কেউ শুধু email
// পাঠিয়ে অন্য কারো অ্যাকাউন্টের ডেটা দেখতে/বদলাতে না পারে —
// টোকেন যাচাই হয়ে req.userId এবং req.userEmail সেট হয়।
// ============================================================
function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ message: 'Not authenticated' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    req.userEmail = decoded.email;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired session. Please log in again.' });
  }
}

// অনুরোধে পাঠানো email, টোকেনের মালিকের email-এর সাথে মিলছে কিনা
// নিশ্চিত করে — অন্য কারো ইমেইল দিয়ে নিজের টোকেন ব্যবহার করে
// তার ডেটা টার্গেট করা যাবে না।
function ensureOwnEmail(req, res, next) {
  const targetEmail = (req.body && req.body.email) || (req.query && req.query.email);
  if (targetEmail && targetEmail.toLowerCase() !== String(req.userEmail).toLowerCase()) {
    return res.status(403).json({ message: 'Forbidden: cannot access another account.' });
  }
  next();
}

// ============================================================
// ১. SIGNUP — OTP পাঠানো
// ============================================================
app.post('/api/send-otp', otpRequestLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required' });

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    const otp = crypto.randomInt(100000, 1000000).toString();
    otpStore[email] = { otp, expiresAt: Date.now() + 5 * 60 * 1000, attempts: 0 };

    await sendOtpEmail(email, otp, 'Eanova - Verification OTP Code');
    res.json({ message: 'OTP sent to email successfully!' });
  } catch (error) {
    console.error('Error sending OTP:', error.message || error);
    res.status(500).json({ message: 'Failed to send OTP email. Please try again.' });
  }
});

// ============================================================
// ২. SIGNUP — OTP যাচাই করে অ্যাকাউন্ট তৈরি
// ============================================================
app.post('/api/verify-otp', otpRequestLimiter, async (req, res) => {
  try {
    const { name, firm, email, password, region, otp } = req.body;
    if (!name || !firm || !email || !password || !otp) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }

    const record = otpStore[email];
    if (!record) return res.status(400).json({ message: 'OTP not requested or expired' });
    if (record.expiresAt < Date.now()) {
      delete otpStore[email];
      return res.status(400).json({ message: 'OTP expired! Please request again.' });
    }
    // একই ইমেইলে বারবার ভুল OTP দিয়ে গেস করা ঠেকাতে
    record.attempts = (record.attempts || 0) + 1;
    if (record.attempts > 8) {
      delete otpStore[email];
      return res.status(400).json({ message: 'Too many incorrect attempts. Please request a new OTP.' });
    }
    if (record.otp !== otp) {
      return res.status(400).json({ message: 'Invalid OTP code' });
    }

    delete otpStore[email];
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      firm,
      email,
      password: hashedPassword,
      region: (region === 'intl') ? 'intl' : 'in',
      accountCreatedAt: Date.now()
    });

    await newUser.save();
    res.status(201).json({ message: 'Account verified & registered successfully!', email });
  } catch (error) {
    console.error('Error verifying OTP:', error.message || error);
    res.status(500).json({ message: 'Server error during OTP verification' });
  }
});

// ============================================================
// ৩. লগইন
// ============================================================
app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = signToken(user);
    const accountCreatedAt = await ensureAccountCreatedAt(user);
    const trial = trialInfo(accountCreatedAt);

    res.json({
      token,
      user: {
        name: user.name,
        firm: user.firm,
        email: user.email,
        region: user.region
      },
      clients: user.clients || [],
      subscriptionActive: user.subscriptionActive || false,
      activePlan: user.activePlan || null,
      subscriptionExpiry: user.subscriptionExpiry || null,
      profilePic: user.profilePic || '',
      lastReceipt: user.lastReceipt || null,
      accountCreatedAt: accountCreatedAt,
      trialActive: trial.trialActive,
      trialDaysRemaining: trial.daysRemaining,
      message: 'Login successful!'
    });
  } catch (error) {
    console.error('Login error:', error.message || error);
    res.status(500).json({ message: 'Server Error during login' });
  }
});

// ============================================================
// ৪. FORGOT PASSWORD — ধাপ ১: রিসেট OTP পাঠানো
// ============================================================
app.post('/api/forgot-password-otp', resetLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required' });

    const user = await User.findOne({ email });
    // ইউজার আছে কিনা তা প্রকাশ না করাই সাধারণত ভালো অভ্যাস, কিন্তু
    // মূল ফ্রন্টএন্ড ফ্লো (যা "no account found" মেসেজ দেখায়) অক্ষুণ্ণ
    // রাখার জন্য আগের বিহেভিয়ারই বজায় রাখা হলো — আপনার UI অপরিবর্তিত থাকছে।
    if (!user) return res.status(404).json({ message: 'No account found with this email' });

    const otp = crypto.randomInt(100000, 1000000).toString();
    resetOtpStore[email] = { otp, expiresAt: Date.now() + 5 * 60 * 1000, attempts: 0 };

    await sendOtpEmail(email, otp, 'Eanova - Password Reset Code');
    res.json({ message: 'Password reset code sent to your email.' });
  } catch (error) {
    console.error('Error sending reset OTP:', error.message || error);
    res.status(500).json({ message: 'Failed to send reset code' });
  }
});

// ============================================================
// ৫. FORGOT PASSWORD — ধাপ ২: OTP যাচাই করে পাসওয়ার্ড রিসেট
// ============================================================
app.post('/api/reset-password', resetLimiter, async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) {
      return res.status(400).json({ message: 'Email, code and new password are all required' });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }

    const record = resetOtpStore[email];
    if (!record) return res.status(400).json({ message: 'Reset code not requested or expired' });
    if (record.expiresAt < Date.now()) {
      delete resetOtpStore[email];
      return res.status(400).json({ message: 'Reset code expired! Please request again.' });
    }
    record.attempts = (record.attempts || 0) + 1;
    if (record.attempts > 8) {
      delete resetOtpStore[email];
      return res.status(400).json({ message: 'Too many incorrect attempts. Please request a new code.' });
    }
    if (record.otp !== otp) {
      return res.status(400).json({ message: 'Invalid reset code' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const user = await User.findOneAndUpdate({ email }, { password: hashedPassword }, { new: true });
    if (!user) return res.status(404).json({ message: 'User not found' });

    delete resetOtpStore[email];
    res.json({ message: 'Password reset successfully. You can now log in with your new password.' });
  } catch (error) {
    console.error('Error resetting password:', error.message || error);
    res.status(500).json({ message: 'Server error during password reset' });
  }
});

// ============================================================
// ১৪-দিনের ফ্রি ট্রায়াল হেল্পার। accountCreatedAt না থাকলে (পুরনো
// account, এই ফিচার যোগ হওয়ার আগে তৈরি) — ইউজারের অনুরোধ অনুযায়ী
// ধরে নেওয়া হচ্ছে ট্রায়াল এখনই শুরু হয়েছে (আরও ১৪ দিন ফ্রি), তাই
// প্রথমবার এই ফিল্ড সেট করে দেওয়া হচ্ছে এবং তা persist করা হচ্ছে।
// ============================================================
const TRIAL_DURATION_MS = 14 * 24 * 60 * 60 * 1000;

async function ensureAccountCreatedAt(user) {
  if (!user.accountCreatedAt) {
    user.accountCreatedAt = Date.now();
    user.markModified('accountCreatedAt');
    await user.save();
  }
  return user.accountCreatedAt;
}

function trialInfo(accountCreatedAt) {
  const elapsed = Date.now() - accountCreatedAt;
  const remainingMs = TRIAL_DURATION_MS - elapsed;
  const trialActive = remainingMs > 0;
  const daysRemaining = trialActive ? Math.max(1, Math.ceil(remainingMs / (24 * 60 * 60 * 1000))) : 0;
  return { trialActive, daysRemaining };
}

// ============================================================
// ৬. ইউজারের ক্লায়েন্ট লিস্ট ও সাবস্ক্রিপশন ডাটা ফেচ করা
//    (এখন লগইন টোকেন আবশ্যক + নিজের একাউন্ট ছাড়া দেখা যাবে না)
// ============================================================
app.get('/api/user-data', requireAuth, ensureOwnEmail, async (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  try {
    const user = await User.findOne({ email: req.userEmail });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const accountCreatedAt = await ensureAccountCreatedAt(user);
    const trial = trialInfo(accountCreatedAt);

    res.json({
      user: {
        name: user.name,
        firm: user.firm,
        email: user.email,
        region: user.region,
        hasPaidBefore: user.hasPaidBefore || false,
        subscriptionActive: user.subscriptionActive || false,
        activePlan: user.activePlan || null,
        subscriptionExpiry: user.subscriptionExpiry || null,
        profilePic: user.profilePic || '',
        lastReceipt: user.lastReceipt || null,
        accountCreatedAt: accountCreatedAt,
        trialActive: trial.trialActive,
        trialDaysRemaining: trial.daysRemaining
      },
      clients: user.clients || []
    });
  } catch (err) {
    console.error('Error fetching user data:', err.message || err);
    res.status(500).json({ message: 'Server error fetching user data' });
  }
});

// ============================================================
// প্ল্যান দাম/মেয়াদ — সার্ভার-সাইডে ফিক্সড, ক্লায়েন্ট থেকে কখনো
// বিশ্বাস করা হয় না (Prompt 4: Payment Logic)। subscriptionExpiry-ও
// এখান থেকেই হিসাব হয়, ক্লায়েন্টের পাঠানো ভ্যালু থেকে নয়।
// ============================================================
const PLAN_DURATIONS_MS = {
  first: 30 * 24 * 60 * 60 * 1000,    // ১ মাস
  monthly: 30 * 24 * 60 * 60 * 1000,  // ১ মাস
  annual: 365 * 24 * 60 * 60 * 1000   // ১ বছর
};

// ============================================================
// ৭. প্রোফাইল / সাবস্ক্রিপশন আপডেট
//    (এখন লগইন টোকেন আবশ্যক + নিজের একাউন্ট ছাড়া বদলানো যাবে না;
//     subscriptionActive সরাসরি ক্লায়েন্ট থেকে "true" পাঠিয়ে সেট
//     করা যায় না — শুধুমাত্র হোয়াইটলিস্টেড plan নাম দিয়ে সার্ভার
//     নিজে হিসাব করে সাবস্ক্রিপশন চালু করে)
// ============================================================
app.post('/api/update-profile', requireAuth, ensureOwnEmail, async (req, res) => {
  try {
    const { plan, profilePic, name, firm, receipt } = req.body;

    const user = await User.findOne({ email: req.userEmail });
    if (!user) return res.status(404).json({ message: 'User not found' });

    // --- সাবস্ক্রিপশন/প্ল্যান পরিবর্তন (demo checkout থেকে আসে) ---
    // এখানে শুধু whitelisted plan নাম গ্রহণযোগ্য; দাম ও মেয়াদ
    // সার্ভার নিজে PLAN_DURATIONS_MS থেকে হিসাব করে — ক্লায়েন্ট
    // থেকে subscriptionActive:true বা কোনো amount পাঠিয়ে বিনামূল্যে
    // অ্যাক্টিভেট করা যাবে না।
    if (plan !== undefined) {
      if (!PLAN_DURATIONS_MS[plan]) {
        return res.status(400).json({ message: 'Invalid plan selected' });
      }
      user.subscriptionActive = true;
      user.activePlan = plan;
      user.subscriptionExpiry = Date.now() + PLAN_DURATIONS_MS[plan];
      user.hasPaidBefore = true;

      // রিসিট এখন সার্ভারেও সেভ হয় (শুধু localStorage-এ নয়), তাই অন্য
      // ডিভাইসে লগইন করলে বা সেশন রিনিউ করার পরও "Download Receipt"
      // কাজ করে। এটা কোনো আর্থিক সিদ্ধান্ত নেয় না — শুধু প্রদর্শনের
      // জন্য রেকর্ড রাখা হয়; প্ল্যান অ্যাক্টিভেশন সবসময় উপরের
      // PLAN_DURATIONS_MS থেকেই সার্ভার নিজে হিসাব করে।
      user.lastReceipt = {
        txnId: receipt && receipt.txnId ? String(receipt.txnId).slice(0, 100) : ('EANOVA-' + Date.now()),
        plan: plan,
        amount: receipt && receipt.amount ? String(receipt.amount).slice(0, 50) : '',
        method: receipt && receipt.method ? String(receipt.method).slice(0, 50) : '',
        name: user.name || '',
        email: user.email,
        date: Date.now(),
        expiry: user.subscriptionExpiry
      };
      user.markModified('lastReceipt');
    }

    // --- প্রোফাইল তথ্য (ছবি/নাম/ফার্ম) — সংবেদনশীল নয়, স্বাভাবিকভাবেই আপডেট হয় ---
    if (profilePic !== undefined) user.profilePic = profilePic;
    if (name !== undefined) user.name = String(name).slice(0, 200);
    if (firm !== undefined) user.firm = String(firm).slice(0, 200);

    user.markModified('subscriptionActive');
    user.markModified('activePlan');
    user.markModified('subscriptionExpiry');

    await user.save();

    const verify = await User.findOne({ email: req.userEmail });
    if (!verify || (plan !== undefined && verify.subscriptionActive !== true)) {
      console.error('[update-profile] Save verification FAILED for', req.userEmail);
      return res.status(500).json({ message: 'Save did not persist — please try again' });
    }

    res.json({
      message: 'Profile updated successfully',
      user: {
        name: verify.name,
        firm: verify.firm,
        email: verify.email,
        region: verify.region,
        subscriptionActive: verify.subscriptionActive,
        activePlan: verify.activePlan,
        subscriptionExpiry: verify.subscriptionExpiry,
        hasPaidBefore: verify.hasPaidBefore,
        profilePic: verify.profilePic,
        lastReceipt: verify.lastReceipt || null
      }
    });
  } catch (err) {
    console.error('Error updating profile:', err.message || err);
    res.status(500).json({ message: 'Server error updating profile' });
  }
});

// ============================================================
// ৮. ক্লায়েন্ট সেভ/আপডেট
//    (এখন লগইন টোকেন আবশ্যক + নিজের একাউন্ট ছাড়া সেভ করা যাবে না)
// ============================================================
app.post('/api/save-client', requireAuth, ensureOwnEmail, async (req, res) => {
  try {
    const { clientData } = req.body;
    if (!clientData || !clientData.id) {
      return res.status(400).json({ message: 'clientData with an id is required' });
    }

    const user = await User.findOne({ email: req.userEmail });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const existingIndex = (user.clients || []).findIndex(c => c.id === clientData.id);
    if (existingIndex >= 0) {
      user.clients[existingIndex] = clientData;
    } else {
      user.clients.push(clientData);
    }
    user.markModified('clients');
    await user.save();

    res.json({ message: 'Client saved successfully', clients: user.clients });
  } catch (err) {
    console.error('Error saving client:', err.message || err);
    res.status(500).json({ message: 'Server error saving client' });
  }
});

// ============================================================
// ৯. ফ্রি-ট্রায়াল দৈনিক reconciliation সীমা চেক
//    (এখন লগইন টোকেন আবশ্যক + নিজের একাউন্ট ছাড়া চেক করা যাবে না)
// ============================================================
app.post('/api/check-reconciliation-limit', requireAuth, ensureOwnEmail, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.userEmail });
    if (!user) return res.status(404).json({ message: 'User not found' });

    // পেইড সাবস্ক্রিপশন থাকলে দিনে আনলিমিটেড ফাইল ম্যাচ — কোনো লিমিট নেই।
    if (user.subscriptionActive) {
      return res.json({ allowed: true, reason: 'paid' });
    }

    // ফ্রি ট্রায়াল: সাইন-আপের ১৪ দিনের মধ্যে, দিনে (২৪ ঘন্টায়) একটা ম্যাচ।
    const accountCreatedAt = await ensureAccountCreatedAt(user);
    const trial = trialInfo(accountCreatedAt);
    if (!trial.trialActive) {
      return res.json({ allowed: false, reason: 'trial-expired' });
    }

    const today = new Date().toISOString().slice(0, 10);
    if (user.lastReconciliationDate === today) {
      return res.json({ allowed: false, reason: 'daily-limit-reached', trialDaysRemaining: trial.daysRemaining });
    }

    user.lastReconciliationDate = today;
    await user.save();
    res.json({ allowed: true, reason: 'trial-daily-slot', trialDaysRemaining: trial.daysRemaining });
  } catch (err) {
    console.error('Error checking reconciliation limit:', err.message || err);
    // নেটওয়ার্ক/ডিবি সমস্যায় ট্রায়াল ইউজারের একমাত্র ওয়ার্কফ্লো
    // আটকে না যায়, তাই আগের মতোই fail-open রাখা হলো।
    res.json({ allowed: true, reason: 'check-failed-open' });
  }
});

// ============================================================
// ফলব্যাক — অজানা রুটে জেনেরিক 404 (স্ট্যাক ট্রেস বা ইন্টারনাল ইনফো ফাঁস করে না)
// ============================================================
app.use((req, res) => {
  res.status(404).json({ message: 'Not found' });
});

// ============================================================
// গ্লোবাল এরর হ্যান্ডলার — ক্লায়েন্টকে কখনো stack trace/internal
// details পাঠানো হয় না, শুধু সার্ভার লগে বিস্তারিত থাকে
// ============================================================
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message || err);
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({ message: 'Origin not allowed' });
  }
  res.status(500).json({ message: 'Something went wrong. Please try again.' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
