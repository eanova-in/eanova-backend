const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
require('dotenv').config();

const User = require('./User');

const app = express();
app.use(express.json());
app.use(cors());

// MongoDB কানেকশন
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB Connected Successfully!'))
  .catch(err => console.log('DB Error:', err));

// মেমোরিতে সাময়িকভাবে OTP ধরে রাখার অবজেক্ট (signup OTP + forgot-password OTP আলাদা key দিয়ে)
const otpStore = {};
const resetOtpStore = {};

// Transporter তৈরি (Gmail App Password দিয়ে)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

function sendOtpEmail(email, otp, subjectLine) {
  return transporter.sendMail({
    from: `"Eanova Support" <${process.env.EMAIL_USER}>`,
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
}

// ============================================================
// ১. SIGNUP — OTP পাঠানো
// ============================================================
app.post('/api/send-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required' });

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore[email] = { otp, expiresAt: Date.now() + 5 * 60 * 1000 };

    await sendOtpEmail(email, otp, 'Eanova - Verification OTP Code');
    res.json({ message: 'OTP sent to email successfully!' });
  } catch (error) {
    console.error('Error sending OTP:', error);
    res.status(500).json({ message: 'Failed to send OTP email' });
  }
});

// ============================================================
// ২. SIGNUP — OTP যাচাই করে অ্যাকাউন্ট তৈরি
// ============================================================
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { name, firm, email, password, region, otp } = req.body;

    const record = otpStore[email];
    if (!record) return res.status(400).json({ message: 'OTP not requested or expired' });
    if (record.expiresAt < Date.now()) {
      delete otpStore[email];
      return res.status(400).json({ message: 'OTP expired! Please request again.' });
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
      region
    });

    await newUser.save();
    res.status(201).json({ message: 'Account verified & registered successfully!', email });
  } catch (error) {
    console.error('Error verifying OTP:', error);
    res.status(500).json({ message: 'Server error during OTP verification' });
  }
});

// ============================================================
// ৩. লগইন
// ============================================================
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'secretkey', { expiresIn: '1d' });

    res.json({
      token,
      user: {
        name: user.name,
        firm: user.firm,
        email: user.email,
        region: user.region
      },
      // Returned directly on login too (not just via /api/user-data) so the
      // dashboard is correct on first paint after logging in on a new device,
      // without waiting for the follow-up sync call.
      clients: user.clients || [],
      subscriptionActive: user.subscriptionActive || false,
      activePlan: user.activePlan || null,
      subscriptionExpiry: user.subscriptionExpiry || null,
      profilePic: user.profilePic || '',
      message: 'Login successful!'
    });
  } catch (error) {
    res.status(500).json({ message: 'Server Error during login' });
  }
});

// ============================================================
// ৪. FORGOT PASSWORD — ধাপ ১: রিসেট OTP পাঠানো
// ============================================================
app.post('/api/forgot-password-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'No account found with this email' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    resetOtpStore[email] = { otp, expiresAt: Date.now() + 5 * 60 * 1000 };

    await sendOtpEmail(email, otp, 'Eanova - Password Reset Code');
    res.json({ message: 'Password reset code sent to your email.' });
  } catch (error) {
    console.error('Error sending reset OTP:', error);
    res.status(500).json({ message: 'Failed to send reset code' });
  }
});

// ============================================================
// ৫. FORGOT PASSWORD — ধাপ ২: OTP যাচাই করে পাসওয়ার্ড রিসেট
// ============================================================
app.post('/api/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) {
      return res.status(400).json({ message: 'Email, code and new password are all required' });
    }

    const record = resetOtpStore[email];
    if (!record) return res.status(400).json({ message: 'Reset code not requested or expired' });
    if (record.expiresAt < Date.now()) {
      delete resetOtpStore[email];
      return res.status(400).json({ message: 'Reset code expired! Please request again.' });
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
    console.error('Error resetting password:', error);
    res.status(500).json({ message: 'Server error during password reset' });
  }
});

// ============================================================
// ৬. ইউজারের ক্লায়েন্ট লিস্ট ও সাবস্ক্রিপশন ডাটা ফেচ করা
// ============================================================
app.get('/api/user-data', async (req, res) => {
  // This response must never be cached by the browser. Without this header,
  // the browser was free to reuse a cached copy from before a purchase and
  // return it as an HTTP 304 — which is exactly what was making a plan
  // that saved correctly on the server still disappear on refresh: the
  // fresh request never actually reached this handler, so even correct
  // server-side data never had a chance to reach the page.
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  try {
    const { email } = req.query;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    // TEMPORARY DIAGNOSTIC — same purpose as the one in /api/update-profile.
    console.log('[DIAG user-data] email queried:', email, '| subscriptionActive found:', user.subscriptionActive, '| _id:', user._id.toString());

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
    res.status(500).json({ message: 'Server error fetching user data' });
  }
});

// ============================================================
// ৭. প্রোফাইল / সাবস্ক্রিপশন আপডেট
//    (প্ল্যান কেনা, প্রোফাইল ছবি বদলানো — এই দুটোই এই একটা রুট দিয়ে হয়)
// ============================================================
app.post('/api/update-profile', async (req, res) => {
  try {
    const { email, subscriptionActive, activePlan, subscriptionExpiry, hasPaidBefore, profilePic, name, firm } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required' });

    // Load the document and set fields directly, then call .save().
    // findOneAndUpdate() with a plain update object was silently not
    // persisting subscriptionActive/activePlan/subscriptionExpiry even
    // though it returned 200 and even echoed back the correct values in
    // its own response — the write simply wasn't landing. Loading the
    // document, assigning fields on it directly, and calling .save()
    // is a completely different Mongoose code path (goes through the
    // document's own change-tracking rather than an update-query
    // builder) and sidesteps whatever was swallowing the update.
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (typeof subscriptionActive === 'boolean') user.subscriptionActive = subscriptionActive;
    if (activePlan !== undefined) user.activePlan = activePlan;
    if (subscriptionExpiry !== undefined) user.subscriptionExpiry = subscriptionExpiry;
    if (typeof hasPaidBefore === 'boolean') user.hasPaidBefore = hasPaidBefore;
    if (profilePic !== undefined) user.profilePic = profilePic;
    if (name !== undefined) user.name = name;
    if (firm !== undefined) user.firm = firm;

    user.markModified('subscriptionActive');
    user.markModified('activePlan');
    user.markModified('subscriptionExpiry');

    await user.save();

    // Immediately re-read from the database (not from the in-memory
    // object just saved) as a hard verification that the write actually
    // landed. If it didn't, fail loudly with a 500 instead of returning
    // a false "success" — the frontend's retry logic (see payBtn
    // handler) already knows how to handle a failed save safely, but it
    // can only do that if a real failure is reported as one.
    const verify = await User.findOne({ email });
    if (!verify || (typeof subscriptionActive === 'boolean' && verify.subscriptionActive !== subscriptionActive)) {
      console.error('[update-profile] Save verification FAILED for', email, '— wrote', subscriptionActive, 'but re-read got', verify && verify.subscriptionActive);
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
    console.error('Error updating profile:', err);
    res.status(500).json({ message: 'Server error updating profile' });
  }
});

// ============================================================
// ৮. ক্লায়েন্ট সেভ/আপডেট
//    আগের ভার্সনে এটা সবসময় $push করত, ফলে reconciliation চালানোর পর
//    একই client-এর জন্য আবার call করলে সেই client duplicate হয়ে array-তে
//    যোগ হত। এখন: id মিলে গেলে সেই client-কে replace করে, না মিললে নতুন
//    client হিসেবে push করে।
// ============================================================
app.post('/api/save-client', async (req, res) => {
  try {
    const { email, clientData } = req.body;
    if (!email || !clientData) return res.status(400).json({ message: 'email and clientData are required' });

    const user = await User.findOne({ email });
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
    console.error('Error saving client:', err);
    res.status(500).json({ message: 'Server error saving client' });
  }
});

// ============================================================
// ৯. ফ্রি-ট্রায়াল দৈনিক reconciliation সীমা চেক
//    ফ্রি ট্রায়ালে থাকা ইউজার প্রতি ক্যালেন্ডার দিনে একবার reconciliation
//    চালাতে পারবে। পেইড সাবস্ক্রিপশন থাকলে কোনো সীমা নেই।
// ============================================================
app.post('/api/check-reconciliation-limit', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (user.subscriptionActive) {
      return res.json({ allowed: true, reason: 'paid' });
    }

    const today = new Date().toISOString().slice(0, 10); // 'YYYY-MM-DD'
    if (user.lastReconciliationDate === today) {
      return res.json({ allowed: false, reason: 'daily-limit-reached' });
    }

    user.lastReconciliationDate = today;
    await user.save();
    res.json({ allowed: true, reason: 'trial-daily-slot' });
  } catch (err) {
    console.error('Error checking reconciliation limit:', err);
    // Fail open rather than blocking a paying customer's workflow over a
    // transient server error — but this only affects trial accounts, since
    // paid accounts return earlier above.
    res.json({ allowed: true, reason: 'check-failed-open' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
