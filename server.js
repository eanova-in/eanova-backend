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

    const newUser = new User({
      name,
      firm,
      email,
      password: hashedPassword,
      region: (region === 'intl') ? 'intl' : 'in'
    });

    // Share & Earn: এই নতুন একাউন্টের নিজস্ব referral code বানানো হলো,
    // আর কেউ refer করে থাকলে (valid code হলে) সেটা referredBy-তে বসানো হলো।
    await assignReferralCode(newUser);
    if (ref) {
      const refCode = String(ref).trim().toUpperCase();
      if (refCode) {
        const referrer = await User.findOne({ referralCode: refCode });
        if (referrer && referrer.email !== email) {
          newUser.referredBy = refCode;
        }
      }
    }

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
      user = new User({
        name: payload.name || email.split('@')[0],
        firm: '',
        email,
        googleId,
        region: 'in',
        profilePic: payload.picture || ''
      });

      // Share & Earn: OTP signup-এর মতোই — নতুন একাউন্টের নিজের referral
      // code বানানো, আর valid ref code থাকলে referredBy বসানো।
      await assignReferralCode(user);
      if (ref) {
        const refCode = String(ref).trim().toUpperCase();
        if (refCode) {
          const referrer = await User.findOne({ referralCode: refCode });
          if (referrer && referrer.email !== email) {
            user.referredBy = refCode;
          }
        }
      }

      await user.save();
    } else if (!user.googleId) {
      // আগে থেকেই ইমেইল/পাসওয়ার্ড দিয়ে account ছিল — এই Google
      // একাউন্টটা তার সাথে link করে দেওয়া হলো, existing password/data
      // কিছুই বদলানো হয় না।
      user.googleId = googleId;
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

// ============================================================
// SHARE & EARN (রেফারেল) — কনস্ট্যান্ট ও হেল্পার
//
// - প্রতিটা successful plan purchase-এ referrer 8% commission পাবে
//   (base amount-এর উপর, GST বাদে), যতদিন referred account থাকবে।
// - commission ৭ দিন hold-এ থাকে (REFERRAL_HOLD_MS) — এই সময়ের মধ্যে
//   referred user যদি refund নেয় (founder manually Razorpay dashboard
//   থেকে refund করে, তারপর /api/admin/mark-refunded কল করে), তাহলে
//   ওই কমিশন 'reversed' হয়ে যাবে।
// - Withdraw করতে minimum ₹100 available balance লাগবে (MIN_WITHDRAWAL_INR)।
// ============================================================
const REFERRAL_COMMISSION_RATE = 0.08;
const REFERRAL_HOLD_MS = 7 * 24 * 60 * 60 * 1000; // ৭ দিন
const MIN_WITHDRAWAL_INR = 100;

// একটা random, unique referral code বানিয়ে user ডকুমেন্টে বসিয়ে দেয়।
// এখনো save করা হয় না — caller-কেই user.save() করতে হবে।
async function assignReferralCode(userDoc) {
  for (let i = 0; i < 6; i++) {
    const candidate = crypto.randomBytes(4).toString('hex').toUpperCase(); // ৮ ক্যারেক্টার
    const exists = await User.findOne({ referralCode: candidate });
    if (!exists) {
      userDoc.referralCode = candidate;
      return candidate;
    }
  }
  // অত্যন্ত বিরল ফলব্যাক — নিজের ডাটাবেস আইডি থেকে বানানো, এটা সবসময় ইউনিক
  const fallback = userDoc._id.toString().slice(-8).toUpperCase();
  userDoc.referralCode = fallback;
  return fallback;
}

// ইমেইল আংশিকভাবে লুকিয়ে দেখায়, referrer-কে referred ব্যক্তির পুরো
// ইমেইল দেখানো হয় না।
function maskEmailServer(email) {
  if (!email) return '';
  const parts = String(email).split('@');
  if (parts.length !== 2) return email;
  const name = parts[0];
  const masked = name.length <= 2 ? (name[0] || '') + '*' : name.slice(0, 2) + '***';
  return masked + '@' + parts[1];
}

// একজন ইউজারের pointsLedger থেকে available / on-hold / total ইত্যাদি হিসাব
// করে — কোনো ডাটাবেস রাইট করে না, শুধু read-only summary।
function summarizePoints(user) {
  const now = Date.now();
  const ledger = user.pointsLedger || [];
  let availableBalance = 0, onHold = 0, totalEarned = 0, withdrawn = 0, reversed = 0;

  const history = ledger.map(function (e) {
    let status = e.status;
    if (e.type === 'earn') {
      totalEarned += e.amount;
      if (e.status === 'reversed') {
        reversed += e.amount;
        status = 'reversed';
      } else if (e.status === 'withdrawn') {
        withdrawn += e.amount;
        status = 'withdrawn';
      } else if (now >= e.availableAt) {
        availableBalance += e.amount;
        status = 'available';
      } else {
        onHold += e.amount;
        status = 'on_hold';
      }
    }
    return {
      id: e.id,
      amount: e.amount,
      planPurchased: e.planPurchased,
      buyerEmailMasked: maskEmailServer(e.buyerEmail),
      createdAt: e.createdAt,
      availableAt: e.availableAt,
      status: status
    };
  });

  history.sort(function (a, b) { return b.createdAt - a.createdAt; });

  return {
    availableBalance: Math.round(availableBalance * 100) / 100,
    onHold: Math.round(onHold * 100) / 100,
    totalEarned: Math.round(totalEarned * 100) / 100,
    withdrawn: Math.round(withdrawn * 100) / 100,
    reversed: Math.round(reversed * 100) / 100,
    history: history
  };
}

// Razorpay-তে সত্যিকারের টাকা দিয়ে plan কেনা হলে এটা কল হয় — buyer-এর
// referredBy থাকলে সেই referrer-কে 8% commission (base amount-এর উপর,
// GST বাদে) points হিসেবে জমা দেয়, ৭ দিনের hold সহ। কোনো ভুল হলেও এটা
// পুরো পেমেন্ট ফ্লো ভেঙে না দেয়ার জন্য নিজের try/catch-এ রাখা।
async function creditReferralCommission(buyerUser, plan, purchaseRef) {
  try {
    if (!buyerUser || !buyerUser.referredBy) return;
    const baseAmount = PLAN_BASE_INR[plan];
    if (!baseAmount) return;

    const referrer = await User.findOne({ referralCode: buyerUser.referredBy });
    if (!referrer || referrer.email === buyerUser.email) return; // self-referral গার্ড

    const commission = Math.round(baseAmount * REFERRAL_COMMISSION_RATE * 100) / 100;
    const now = Date.now();

    referrer.pointsLedger = referrer.pointsLedger || [];
    referrer.pointsLedger.push({
      id: crypto.randomUUID(),
      type: 'earn',
      amount: commission,
      planPurchased: plan,
      buyerEmail: buyerUser.email,
      purchaseRef: purchaseRef,
      createdAt: now,
      availableAt: now + REFERRAL_HOLD_MS,
      status: 'active'
    });
    referrer.markModified('pointsLedger');
    await referrer.save();
  } catch (e) {
    console.error('[referral] commission credit failed:', e.message || e);
  }
}

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

    // Share & Earn: এই পেমেন্ট real টাকা দিয়ে হয়েছে confirm হওয়ার পরই
    // referrer-কে (থাকলে) 8% commission credit করা হচ্ছে। এটা ব্যর্থ
    // হলেও পুরো পেমেন্ট রেসপন্স আটকাবে না (নিজের try/catch ভিতরে আছে)।
    await creditReferralCommission(verify, plan, razorpay_payment_id);

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
// ১০. SHARE & EARN — নিজের referral code, লিংক, ও পয়েন্টস সামারি
//     (লগইন টোকেন আবশ্যক)
// ============================================================
app.get('/api/referral/info', requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.userEmail });
    if (!user) return res.status(404).json({ message: 'User not found' });

    // পুরনো একাউন্ট (এই ফিচার আসার আগের) হলে এখনই একটা referral code
    // বসিয়ে দেওয়া হচ্ছে, যাতে সবাই এই ফিচার ব্যবহার করতে পারে।
    if (!user.referralCode) {
      await assignReferralCode(user);
      await user.save();
    }

    const points = summarizePoints(user);

    // History-তে যে কেউ এই referral code দিয়ে সাইন-আপ করেছে তার নাম +
    // স্ট্যাটাস দেখানো হয় — শুধু যারা কিনেছে তারা না, যারা শুধু একাউন্ট
    // খুলেছে কিন্তু এখনো কোনো প্ল্যান কেনেনি তারাও (pending হিসেবে)।
    const referredDocs = await User.find({ referredBy: user.referralCode })
      .select('name email hasPaidBefore');
    const earnedByEmail = {};
    (user.pointsLedger || []).forEach(function (e) {
      if (e.type === 'earn' && e.status !== 'reversed') {
        earnedByEmail[e.buyerEmail] = (earnedByEmail[e.buyerEmail] || 0) + e.amount;
      }
    });
    const referredAccounts = referredDocs.map(function (d) {
      return {
        name: d.name || maskEmailServer(d.email),
        status: d.hasPaidBefore ? 'success' : 'pending',
        totalEarned: Math.round((earnedByEmail[d.email] || 0) * 100) / 100
      };
    });

    res.json({
      referralCode: user.referralCode,
      referralLink: 'https://www.eanova.in/?ref=' + user.referralCode,
      points: points,
      referredAccounts: referredAccounts,
      minWithdrawalInr: MIN_WITHDRAWAL_INR,
      withdrawalRequests: (user.withdrawalRequests || [])
        .slice()
        .sort(function (a, b) { return b.createdAt - a.createdAt; })
    });
  } catch (err) {
    console.error('Error fetching referral info:', err.message || err);
    res.status(500).json({ message: 'Server error fetching referral info' });
  }
});

// ============================================================
// ১১. SHARE & EARN — উইথড্রয়াল রিকোয়েস্ট
//     (আসল টাকা পাঠানো ম্যানুয়ালি হবে — এই রুট শুধু রিকোয়েস্টটা
//     রেকর্ড করে রাখে এবং সেই মুহূর্তের available পয়েন্ট lock করে,
//     যাতে একই পয়েন্ট দুইবার withdraw request করা না যায়। ইউজারকে
//     Live Chat / email-এ গিয়ে বিস্তারিত (bank/UPI QR) জানাতে হবে,
//     তারপর founder ম্যানুয়ালি টাকা পাঠাবে।)
// ============================================================
app.post('/api/points/request-withdrawal', requireAuth, async (req, res) => {
  try {
    const { contactMethod, payoutMethod, payoutDetails } = req.body;
    if (!['livechat', 'email'].includes(contactMethod)) {
      return res.status(400).json({ message: 'Please choose Live Chat or Email as your contact method.' });
    }
    if (!['bank', 'upi_qr'].includes(payoutMethod)) {
      return res.status(400).json({ message: 'Please choose how you want to receive payment (bank details or UPI QR).' });
    }

    const user = await User.findOne({ email: req.userEmail });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const points = summarizePoints(user);
    if (points.availableBalance < MIN_WITHDRAWAL_INR) {
      return res.status(400).json({
        message: 'You need at least ₹' + MIN_WITHDRAWAL_INR + ' in available balance to withdraw. Newly earned points also need 7 days to clear first.'
      });
    }

    const now = Date.now();
    const amount = points.availableBalance;

    // এই মুহূর্তে যা "available" ছিল, সেই ledger entry-গুলোকে withdrawn
    // মার্ক করে দেওয়া হচ্ছে, যাতে দ্বিতীয়বার একই পয়েন্ট withdraw
    // request করা না যায়।
    (user.pointsLedger || []).forEach(function (e) {
      if (e.type === 'earn' && e.status === 'active' && now >= e.availableAt) {
        e.status = 'withdrawn';
      }
    });

    user.withdrawalRequests = user.withdrawalRequests || [];
    user.withdrawalRequests.push({
      id: crypto.randomUUID(),
      amount: amount,
      contactMethod: contactMethod,
      payoutMethod: payoutMethod,
      payoutDetails: String(payoutDetails || '').slice(0, 500),
      createdAt: now,
      status: 'pending'
    });

    user.markModified('pointsLedger');
    user.markModified('withdrawalRequests');
    await user.save();

    res.json({
      message: 'Withdrawal request received for ₹' + amount + '. Please continue on ' +
        (contactMethod === 'livechat' ? 'Live Chat' : 'email') + ' to complete verification and receive payment.',
      amount: amount
    });
  } catch (err) {
    console.error('Error requesting withdrawal:', err.message || err);
    res.status(500).json({ message: 'Server error requesting withdrawal' });
  }
});

// ============================================================
// ১২. ADMIN — Refund হলে referral commission reverse করা
//     (লগইন টোকেন নয়, বরং ADMIN_SECRET এনভায়রনমেন্ট ভ্যারিয়েবল দিয়ে
//     প্রোটেক্টেড — founder নিজে Razorpay dashboard থেকে refund করার
//     পর এই রুটটা ম্যানুয়ালি (curl/Postman দিয়ে) কল করবে। ADMIN_SECRET
//     সেট করা না থাকলে এই রুট নিরাপদে সবসময় বন্ধ থাকবে, কখনো ভুল করে
//     খোলা থাকবে না।)
// ============================================================
app.post('/api/admin/mark-refunded', async (req, res) => {
  try {
    if (!process.env.ADMIN_SECRET) {
      return res.status(500).json({ message: 'Admin actions are not configured on the server yet (ADMIN_SECRET not set).' });
    }
    const { adminSecret, razorpayPaymentId } = req.body;
    if (adminSecret !== process.env.ADMIN_SECRET) {
      return res.status(403).json({ message: 'Invalid admin secret' });
    }
    if (!razorpayPaymentId) {
      return res.status(400).json({ message: 'razorpayPaymentId is required' });
    }

    const referrer = await User.findOne({ 'pointsLedger.purchaseRef': razorpayPaymentId });
    if (!referrer) {
      return res.status(404).json({ message: 'No referral commission found for this payment ID — maybe this purchase had no referrer.' });
    }

    let reversedAmount = 0;
    let alreadySettled = false;
    (referrer.pointsLedger || []).forEach(function (e) {
      if (e.purchaseRef === razorpayPaymentId && e.type === 'earn') {
        if (e.status === 'active') {
          e.status = 'reversed';
          reversedAmount = e.amount;
        } else {
          alreadySettled = true;
        }
      }
    });
    referrer.markModified('pointsLedger');
    await referrer.save();

    if (reversedAmount > 0) {
      return res.json({
        message: 'Reversed ₹' + reversedAmount + ' referral commission for ' + referrer.email + '.',
        referrerEmail: referrer.email,
        reversedAmount: reversedAmount
      });
    }
    return res.json({
      message: alreadySettled
        ? 'That commission was already withdrawn or already reversed — no automatic change made. Adjust manually in Atlas if the payout already went out.'
        : 'Found the referrer but no matching active commission entry for this payment ID.',
      referrerEmail: referrer.email,
      reversedAmount: 0
    });
  } catch (err) {
    console.error('Error marking refund:', err.message || err);
    res.status(500).json({ message: 'Server error processing refund reversal' });
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
