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
const ReferralCommission = require('./ReferralCommission');
const WithdrawalRequest = require('./WithdrawalRequest');

// ============================================================
// রেফারেল প্রোগ্রাম — হেল্পার
// ============================================================
const REFERRAL_COMMISSION_RATE = 0.08;   // referred user-এর pre-GST প্ল্যান amount-এর 8%
const REFERRAL_UNLOCK_MS = 7 * 24 * 60 * 60 * 1000; // ৭ দিন লক থাকবে, তারপর withdraw করা যাবে
const REFERRAL_MIN_WITHDRAW = 100; // ₹100

function generateReferralCodeCandidate() {
  // ছোট, সহজে টাইপ/শেয়ার করা যায় এমন কোড — কিন্তু guess করা কঠিন হওয়ার
  // জন্য যথেষ্ট এলোমেলো (৮ অক্ষর, base36, ~41 বিট এনট্রপি)।
  return crypto.randomBytes(6).toString('base64url').replace(/[^a-zA-Z0-9]/g, '').slice(0, 8).toUpperCase();
}
async function generateUniqueReferralCode() {
  for (let attempt = 0; attempt < 8; attempt++) {
    const candidate = generateReferralCodeCandidate();
    const exists = await User.findOne({ referralCode: candidate }).select('_id');
    if (!exists) return candidate;
  }
  // অত্যন্ত অসম্ভব (৮ বারেও collision) — timestamp যোগ করে নিশ্চিত ইউনিক করা
  return generateReferralCodeCandidate() + Date.now().toString(36).slice(-4).toUpperCase();
}

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
    const { name, firm, email, password, region, otp, ref } = req.body;
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

    // রেফারেল — কোড সত্যিই কোনো existing user-এর হলেই, এবং কারো নিজের
    // ইমেইলের সাথে না মিললেই (trivial self-referral আটকানো) সেট হবে।
    // referredBy একবার এখানেই সেট হয়, পরে আর কখনো বদলানো যায় না।
    let referredByCode = null;
    if (ref && typeof ref === 'string') {
      const referrer = await User.findOne({ referralCode: ref.trim().toUpperCase() }).select('_id email referralCode');
      if (referrer && referrer.email.toLowerCase() !== email.toLowerCase()) {
        referredByCode = referrer.referralCode;
      }
    }
    const myReferralCode = await generateUniqueReferralCode();

    const newUser = new User({
      name,
      firm,
      email,
      password: hashedPassword,
      region: (region === 'intl') ? 'intl' : 'in',
      referralCode: myReferralCode,
      referredBy: referredByCode
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

    // Backfill: রেফারেল ফিচার আসার আগে যাদের account হয়েছিল, তাদের
    // referralCode ছিল না — পরের যেকোনো login-এই একবার lazily বানিয়ে
    // দেওয়া হচ্ছে, আলাদা migration script ছাড়াই।
    if (!user.referralCode) {
      user.referralCode = await generateUniqueReferralCode();
      await user.save();
    }

    const token = signToken(user);

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
      message: 'Login successful!'
    });
  } catch (error) {
    console.error('Login error:', error.message || error);
    res.status(500).json({ message: 'Server Error during login' });
  }
});

// ============================================================
// ৩.৫ — GOOGLE SIGN-IN (নতুন, সম্পূর্ণ আলাদা রুট — উপরের OTP-ভিত্তিক
//        signup/login/forgot-password এর একটা লাইনও এখানে ছোঁয়া হয়নি)
//
// ফ্রন্টএন্ড থেকে Google Identity Services যে "credential" (একটা ID
// token / JWT) পাঠায়, সেটা এখানে সরাসরি Google-এর নিজস্ব tokeninfo
// endpoint দিয়ে verify করা হয় — কোনো নতুন npm প্যাকেজ (google-auth-library
// ইত্যাদি) ইনস্টল করার দরকার নেই, Node-এর built-in fetch দিয়েই হয়।
//
// GOOGLE_CLIENT_ID env variable যোগ করা must — Render-এ Environment
// ট্যাবে গিয়ে বসিয়ে দিতে হবে (মান: আপনার Google Cloud Console-এর
// OAuth Client ID, যেমন 263544387024-....apps.googleusercontent.com)।
// এই ভ্যারিয়েবল ছাড়া রুটটা নিরাপদে সবসময় 500 দেবে, কখনো ভুল করে
// কারো টোকেন গ্রহণ করবে না।
// ============================================================
app.post('/api/google-login', loginLimiter, async (req, res) => {
  try {
    if (!process.env.GOOGLE_CLIENT_ID) {
      console.error('GOOGLE_CLIENT_ID env variable is not set — refusing Google sign-in.');
      return res.status(500).json({ message: 'Google sign-in is not configured on the server yet.' });
    }

    const { credential, ref } = req.body;
    if (!credential) return res.status(400).json({ message: 'Google credential is required' });

    // Google নিজেই এই টোকেনটা যাচাই করে দেয় — স্বাক্ষর (signature),
    // মেয়াদ (expiry), এবং কোন অ্যাপের জন্য ইস্যু হয়েছে সব চেক করা থাকে।
    // আমরা শুধু নিশ্চিত করি এটা আমাদেরই Client ID-র জন্য ইস্যু হয়েছে,
    // অন্য কোনো Google app-এর টোকেন যেন গ্রহণ না হয়।
    let payload;
    try {
      const verifyRes = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(credential));
      if (!verifyRes.ok) {
        return res.status(401).json({ message: 'Invalid or expired Google credential' });
      }
      payload = await verifyRes.json();
    } catch (verifyErr) {
      console.error('Google tokeninfo verification failed:', verifyErr.message || verifyErr);
      return res.status(502).json({ message: 'Could not verify Google credential right now. Please try again.' });
    }

    if (payload.aud !== process.env.GOOGLE_CLIENT_ID) {
      return res.status(401).json({ message: 'Invalid Google credential' });
    }
    if (payload.email_verified !== 'true' && payload.email_verified !== true) {
      return res.status(401).json({ message: 'This Google account\'s email is not verified' });
    }
    if (!payload.email) {
      return res.status(400).json({ message: 'Google did not provide an email address' });
    }

    const email = payload.email;
    const googleId = payload.sub;

    let user = await User.findOne({ email });
    if (!user) {
      // একদম নতুন — Google নিজেই ইমেইল ভেরিফাই করে দিয়েছে, তাই আলাদা
      // OTP লাগবে না। firm name খালি রাখা হলো, ইউজার পরে প্রোফাইল থেকে
      // ভরে নিতে পারবে — password নেই কারণ এই একাউন্ট শুধু Google দিয়েই
      // লগইন করবে।
      let referredByCode = null;
      if (ref && typeof ref === 'string') {
        const referrer = await User.findOne({ referralCode: ref.trim().toUpperCase() }).select('_id email referralCode');
        if (referrer && referrer.email.toLowerCase() !== email.toLowerCase()) {
          referredByCode = referrer.referralCode;
        }
      }
      const myReferralCode = await generateUniqueReferralCode();
      user = new User({
        name: payload.name || email.split('@')[0],
        firm: '',
        email,
        googleId,
        region: 'in',
        profilePic: payload.picture || '',
        referralCode: myReferralCode,
        referredBy: referredByCode
      });
      await user.save();
    } else if (!user.googleId) {
      // আগে থেকেই ইমেইল/পাসওয়ার্ড দিয়ে account ছিল — এই Google
      // একাউন্টটা তার সাথে link করে দেওয়া হলো, existing password/data
      // কিছুই বদলানো হয় না।
      user.googleId = googleId;
      await user.save();
    }

    // Backfill: রেফারেল ফিচার আসার আগে যাদের account হয়েছিল, তাদের
    // referralCode ছিল না — পরের যেকোনো login-এই একবার lazily বানিয়ে
    // দেওয়া হচ্ছে, আলাদা migration script ছাড়াই।
    if (!user.referralCode) {
      user.referralCode = await generateUniqueReferralCode();
      await user.save();
    }

    const token = signToken(user);
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
      message: 'Login successful!'
    });
  } catch (error) {
    console.error('Google login error:', error.message || error);
    res.status(500).json({ message: 'Server error during Google login' });
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
// ৬. ইউজারের ক্লায়েন্ট লিস্ট ও সাবস্ক্রিপশন ডাটা ফেচ করা
//    (এখন লগইন টোকেন আবশ্যক + নিজের একাউন্ট ছাড়া দেখা যাবে না)
// ============================================================
app.get('/api/user-data', requireAuth, ensureOwnEmail, async (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  try {
    const user = await User.findOne({ email: req.userEmail });
    if (!user) return res.status(404).json({ message: 'User not found' });

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
        profilePic: user.profilePic || ''
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
// ৬.৫ — RAZORPAY আসল পেমেন্ট (নতুন, সম্পূর্ণ আলাদা রুট জোড়া —
//        update-profile রুটের একটা লাইনও এখানে ছোঁয়া হয়নি; শুধু
//        payment verify হওয়ার পর ওই রুটটা যা করে (subscription চালু),
//        ঠিক সেই একই কাজ এখানে আলাদাভাবে করা হয়েছে)
//
// দাম ও GST সম্পূর্ণ সার্ভার-সাইডে ফিক্সড, ক্লায়েন্ট থেকে amount
// পাঠিয়ে কম দামে কেনা যাবে না — শুধু plan-এর নাম পাঠানো হয়, দাম
// এখান থেকেই হিসাব হয় (frontend-এর currentPlanPrice()-এর 'in'
// region-এর সাথে হুবহু মেলানো)।
//
// RAZORPAY_KEY_ID এবং RAZORPAY_KEY_SECRET env variable দুটো Render-এ
// বসাতে হবে — না থাকলে এই রুট দুটো নিরাপদে error দেবে, কখনো ভুল করে
// বিনামূল্যে subscription চালু করবে না।
// ============================================================
const PLAN_BASE_INR = {
  first: 99,
  monthly: 199,
  annual: 1800
};
const GST_RATE = 0.18;

app.post('/api/razorpay/create-order', requireAuth, async (req, res) => {
  try {
    if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
      console.error('RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET env variable(s) not set — refusing to create order.');
      return res.status(500).json({ message: 'Payments are not configured on the server yet.' });
    }
    const { plan } = req.body;
    if (!PLAN_BASE_INR[plan]) {
      return res.status(400).json({ message: 'Invalid plan selected' });
    }

    const user = await User.findOne({ email: req.userEmail });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const baseAmount = PLAN_BASE_INR[plan];
    const gstAmount = Math.round(baseAmount * GST_RATE * 100) / 100;
    const totalAmount = Math.round((baseAmount + gstAmount) * 100) / 100;
    const amountInPaise = Math.round(totalAmount * 100);

    const authHeader = 'Basic ' + Buffer.from(process.env.RAZORPAY_KEY_ID + ':' + process.env.RAZORPAY_KEY_SECRET).toString('base64');
    let order;
    try {
      const orderRes = await fetch('https://api.razorpay.com/v1/orders', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': authHeader },
        body: JSON.stringify({
          amount: amountInPaise,
          currency: 'INR',
          // Receipt is just a reference string for your own records — kept
          // short and free of personal data (no full email) since it may
          // show up in Razorpay's dashboard/exports.
          receipt: 'eanova_' + req.userId + '_' + Date.now(),
          notes: { plan: plan, userId: req.userId }
        })
      });
      if (!orderRes.ok) {
        const errBody = await orderRes.text();
        console.error('Razorpay order creation failed:', errBody);
        return res.status(502).json({ message: 'Could not start payment right now. Please try again.' });
      }
      order = await orderRes.json();
    } catch (orderErr) {
      console.error('Razorpay order request failed:', orderErr.message || orderErr);
      return res.status(502).json({ message: 'Could not reach the payment provider. Please try again.' });
    }

    res.json({
      orderId: order.id,
      amount: amountInPaise,
      currency: 'INR',
      keyId: process.env.RAZORPAY_KEY_ID,
      name: user.name || '',
      email: user.email
    });
  } catch (error) {
    console.error('Create order error:', error.message || error);
    res.status(500).json({ message: 'Server error while starting payment' });
  }
});

app.post('/api/razorpay/verify-payment', requireAuth, async (req, res) => {
  try {
    if (!process.env.RAZORPAY_KEY_SECRET) {
      console.error('RAZORPAY_KEY_SECRET env variable not set — refusing to verify payment.');
      return res.status(500).json({ message: 'Payments are not configured on the server yet.' });
    }
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, plan } = req.body;
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({ message: 'Missing payment details' });
    }
    if (!PLAN_DURATIONS_MS[plan]) {
      return res.status(400).json({ message: 'Invalid plan selected' });
    }

    // Razorpay-র নিজস্ব নিয়ম: HMAC-SHA256("order_id|payment_id", key_secret)
    // — এটা মিললেই বোঝা যায় রেসপন্সটা সত্যিই Razorpay পাঠিয়েছে, কেউ
    // browser console থেকে ভুয়া "success" বানিয়ে পাঠায়নি।
    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(razorpay_order_id + '|' + razorpay_payment_id)
      .digest('hex');

    const sigBuffer = Buffer.from(razorpay_signature, 'utf8');
    const expectedBuffer = Buffer.from(expectedSignature, 'utf8');
    const signatureValid = sigBuffer.length === expectedBuffer.length &&
      crypto.timingSafeEqual(sigBuffer, expectedBuffer);

    if (!signatureValid) {
      console.error('[razorpay/verify-payment] Signature mismatch for', req.userEmail, 'order', razorpay_order_id);
      return res.status(400).json({ message: 'Payment verification failed. If money was deducted, please contact support.' });
    }

    const user = await User.findOne({ email: req.userEmail });
    if (!user) return res.status(404).json({ message: 'User not found' });

    // রেফারেল কমিশন শুধু কারো *প্রথম* সফল পেমেন্টেই দেওয়া হয় — তাই এই
    // flag-টা overwrite করার আগেই capture করে রাখা হচ্ছে।
    const isFirstEverPurchase = !user.hasPaidBefore;

    // ঠিক update-profile রুট যা করে সেই একই activation — এখানে আলাদাভাবে
    // লেখা হলো যাতে সেই existing রুটটা একদম অক্ষত থাকে।
    user.subscriptionActive = true;
    user.activePlan = plan;
    user.subscriptionExpiry = Date.now() + PLAN_DURATIONS_MS[plan];
    user.hasPaidBefore = true;
    user.markModified('subscriptionActive');
    user.markModified('activePlan');
    user.markModified('subscriptionExpiry');
    await user.save();

    const verify = await User.findOne({ email: req.userEmail });
    if (!verify || verify.subscriptionActive !== true) {
      console.error('[razorpay/verify-payment] Save verification FAILED for', req.userEmail);
      return res.status(500).json({ message: 'Payment verified but activation failed to save — please contact support with your payment ID: ' + razorpay_payment_id });
    }

    // রেফারেল কমিশন — শুধুমাত্র (ক) এটা এই user-এর জীবনের প্রথম পেমেন্ট
    // হলে, এবং (খ) সে কারো রেফারেল লিংক দিয়ে account খুলেছিল। কখনো
    // payment-এর মূল response-কে ব্যর্থ হতে দেওয়া হয় না এই কারণে — টাকা
    // তো সত্যিই কাটা হয়ে গেছে, referral-crediting ব্যর্থ হলে সেটা শুধু
    // log হবে, customer কখনো এর জন্য আটকে থাকবে না।
    if (isFirstEverPurchase && verify.referredBy) {
      try {
        const referrer = await User.findOne({ referralCode: verify.referredBy }).select('_id');
        if (referrer) {
          const baseAmount = PLAN_BASE_INR[plan] || 0;
          const commissionAmount = Math.round(baseAmount * REFERRAL_COMMISSION_RATE * 100) / 100;
          if (commissionAmount > 0) {
            await ReferralCommission.create({
              referrerId: referrer._id,
              referredUserId: verify._id,
              referredUserName: verify.name || '',
              referredUserEmail: verify.email,
              plan: plan,
              baseAmount: baseAmount,
              commissionAmount: commissionAmount,
              razorpayPaymentId: razorpay_payment_id,
              creditedAt: Date.now(),
              unlocksAt: Date.now() + REFERRAL_UNLOCK_MS,
              status: 'active'
            });
          }
        }
      } catch (refErr) {
        // razorpayPaymentId-এর unique index থাকায়, এই রুট কখনো ভুল করে
        // দুবার call হলেও duplicate commission তৈরি হবে না — এখানে শুধু
        // সেই duplicate-key error (বা অন্য কোনো unexpected error) log
        // হচ্ছে, payment success response-এ কোনো প্রভাব পড়বে না।
        console.error('[razorpay/verify-payment] Referral commission crediting failed (payment itself still succeeded):', refErr.message || refErr);
      }
    }

    res.json({
      message: 'Payment verified and subscription activated!',
      razorpayPaymentId: razorpay_payment_id,
      user: {
        name: verify.name,
        firm: verify.firm,
        email: verify.email,
        region: verify.region,
        subscriptionActive: verify.subscriptionActive,
        activePlan: verify.activePlan,
        subscriptionExpiry: verify.subscriptionExpiry,
        hasPaidBefore: verify.hasPaidBefore,
        profilePic: verify.profilePic
      }
    });
  } catch (error) {
    console.error('Verify payment error:', error.message || error);
    res.status(500).json({ message: 'Server error while verifying payment' });
  }
});

// ============================================================
// ৬.৬ — রেফারেল ড্যাশবোর্ড ও উইথড্র রিকোয়েস্ট (নতুন, আলাদা রুট)
//
// একজন ব্যবহারকারী শুধু নিজের রেফারেল-এর তথ্যই দেখতে পারবে — token থেকে
// req.userEmail বের করেই query করা হয়, কারো ID পাঠিয়ে অন্যের ড্যাশবোর্ড
// দেখার কোনো উপায় নেই। রেফার করা মানুষদের নাম ছাড়া আর কিছু (ইমেইল,
// প্ল্যান, টাকার অঙ্ক) কখনো দেখানো হয় না।
// ============================================================
app.get('/api/referral/dashboard', requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.userEmail });
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (!user.referralCode) {
      user.referralCode = await generateUniqueReferralCode();
      await user.save();
    }

    const referredUsers = await User.find({ referredBy: user.referralCode }).select('_id name');
    const commissions = await ReferralCommission.find({ referrerId: user._id });

    const successfulReferredIds = new Set(commissions.map(c => String(c.referredUserId)));
    const now = Date.now();

    let withdrawableBalance = 0, lockedBalance = 0, lifetimeEarned = 0;
    commissions.forEach(c => {
      if (c.status === 'active') {
        lifetimeEarned += c.commissionAmount;
        if (c.unlocksAt <= now) withdrawableBalance += c.commissionAmount;
        else lockedBalance += c.commissionAmount;
      } else if (c.status === 'withdrawn') {
        lifetimeEarned += c.commissionAmount;
      }
      // 'reversed' কমিশন কোনো হিসাবেই যোগ হয় না
    });
    withdrawableBalance = Math.round(withdrawableBalance * 100) / 100;
    lockedBalance = Math.round(lockedBalance * 100) / 100;
    lifetimeEarned = Math.round(lifetimeEarned * 100) / 100;

    const referredList = referredUsers.map(r => ({
      name: r.name || 'Unnamed',
      status: successfulReferredIds.has(String(r._id)) ? 'successful' : 'pending'
    }));

    res.json({
      referralCode: user.referralCode,
      withdrawableBalance,
      lockedBalance,
      lifetimeEarned,
      minWithdraw: REFERRAL_MIN_WITHDRAW,
      referredUsers: referredList
    });
  } catch (error) {
    console.error('Referral dashboard error:', error.message || error);
    res.status(500).json({ message: 'Server error while loading referral dashboard' });
  }
});

app.post('/api/referral/withdraw-request', requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.userEmail });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const now = Date.now();
    const commissions = await ReferralCommission.find({ referrerId: user._id, status: 'active' });
    let withdrawableBalance = 0;
    commissions.forEach(c => { if (c.unlocksAt <= now) withdrawableBalance += c.commissionAmount; });
    withdrawableBalance = Math.round(withdrawableBalance * 100) / 100;

    if (withdrawableBalance < REFERRAL_MIN_WITHDRAW) {
      return res.status(400).json({
        message: `Minimum withdrawal is ₹${REFERRAL_MIN_WITHDRAW}. Your current withdrawable balance is ₹${withdrawableBalance}.`,
        withdrawableBalance
      });
    }

    // একই সময়ে একাধিকবার ক্লিক করলে একাধিক pending request তৈরি না হোক —
    // আগে থেকে pending থাকলে সেটাই আবার ফেরত দেওয়া হচ্ছে, নতুন করে বানানো
    // হচ্ছে না।
    let existing = await WithdrawalRequest.findOne({ userId: user._id, status: 'pending' });
    if (!existing) {
      existing = await WithdrawalRequest.create({
        userId: user._id,
        userEmail: user.email,
        userName: user.name || '',
        amount: withdrawableBalance,
        requestedAt: now
      });
    }

    res.json({
      message: 'Withdrawal request received. Please contact our team to complete it.',
      contactEmail: 'eanova.in@gmail.com',
      amount: existing.amount
    });
  } catch (error) {
    console.error('Withdrawal request error:', error.message || error);
    res.status(500).json({ message: 'Server error while requesting withdrawal' });
  }
});

// ============================================================
// ৭. প্রোফাইল / সাবস্ক্রিপশন আপডেট
//    (এখন লগইন টোকেন আবশ্যক + নিজের একাউন্ট ছাড়া বদলানো যাবে না;
//     subscriptionActive সরাসরি ক্লায়েন্ট থেকে "true" পাঠিয়ে সেট
//     করা যায় না — শুধুমাত্র হোয়াইটলিস্টেড plan নাম দিয়ে সার্ভার
//     নিজে হিসাব করে সাবস্ক্রিপশন চালু করে)
// ============================================================
app.post('/api/update-profile', requireAuth, ensureOwnEmail, async (req, res) => {
  try {
    const { plan, profilePic, name, firm } = req.body;

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
        profilePic: verify.profilePic
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

    if (user.subscriptionActive) {
      return res.json({ allowed: true, reason: 'paid' });
    }

    const today = new Date().toISOString().slice(0, 10);
    if (user.lastReconciliationDate === today) {
      return res.json({ allowed: false, reason: 'daily-limit-reached' });
    }

    user.lastReconciliationDate = today;
    await user.save();
    res.json({ allowed: true, reason: 'trial-daily-slot' });
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
