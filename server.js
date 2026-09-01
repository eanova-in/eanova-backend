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

// মেমোরিতে সাময়িকভাবে OTP ধরে রাখার অবজেক্ট
const otpStore = {};
const resetOtpStore = {};

// ============================================================
// ✅ Gmail Transporter – IPv4 ফোর্স + টাইমআউট বাড়ানো
// ============================================================
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false, // TLS
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  family: 4,                // ← IPv4 বাধ্য
  connectionTimeout: 10000,
  greetingTimeout: 10000,
  socketTimeout: 10000,
  pool: true,
  maxConnections: 1,
  rateLimit: 5
});

// ট্রান্সপোর্টার ভেরিফাই (ডিবাগ)
transporter.verify(function(error, success) {
  if (error) {
    console.log('SMTP connection error:', error);
  } else {
    console.log('SMTP server is ready to send emails');
  }
});

// ============================================================
// OTP ইমেইল পাঠানোর ফাংশন
// ============================================================
async function sendOtpEmail(email, otp, subjectLine) {
  const mailOptions = {
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
  };
  
  try {
    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent successfully to:', email);
    return info;
  } catch (err) {
    console.error('SendMail error:', err);
    throw err;
  }
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
    res.status(500).json({ message: 'Failed to send OTP email. Please try again.' });
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
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  try {
    const { email } = req.query;
    const user = await User.findOne({ email });
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
    res.status(500).json({ message: 'Server error fetching user data' });
  }
});

// ============================================================
// ৭. প্রোফাইল / সাবস্ক্রিপশন আপডেট
// ============================================================
app.post('/api/update-profile', async (req, res) => {
  try {
    const { email, subscriptionActive, activePlan, subscriptionExpiry, hasPaidBefore, profilePic, name, firm } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required' });

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

    const verify = await User.findOne({ email });
    if (!verify || (typeof subscriptionActive === 'boolean' && verify.subscriptionActive !== subscriptionActive)) {
      console.error('[update-profile] Save verification FAILED for', email);
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

    const today = new Date().toISOString().slice(0, 10);
    if (user.lastReconciliationDate === today) {
      return res.json({ allowed: false, reason: 'daily-limit-reached' });
    }

    user.lastReconciliationDate = today;
    await user.save();
    res.json({ allowed: true, reason: 'trial-daily-slot' });
  } catch (err) {
    console.error('Error checking reconciliation limit:', err);
    res.json({ allowed: true, reason: 'check-failed-open' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
