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

// CORS কনফিগারেশন (যেকোনো ফ্রন্টএন্ড ডোমেইন ও Netlify থেকে কানেকশন এলাও করার জন্য)
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// MongoDB কানেকশন
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB Connected Successfully!'))
  .catch(err => console.log('DB Error:', err));

// মেমোরিতে সাময়িকভাবে OTP ধরে রাখার অবজেক্ট
const otpStore = {};

// Gmail Transporter (IPv4 ফোর্স করা হয়েছে)
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false
  },
  family: 4   // ← এই লাইনটি IPv6 সমস্যা সমাধান করবে
});

// সহায়ক ফাংশন: ইমেইলে OTP পাঠানো
const sendOtpEmail = async (email, otp, subjectTitle) => {
  const mailOptions = {
    from: `"Eanova Support" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: `Eanova - ${subjectTitle}`,
    html: `
      <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #f4f4f4;">
        <h2 style="color: #333;">Eanova Verification</h2>
        <p>Your OTP code for ${subjectTitle.toLowerCase()} is:</p>
        <h1 style="color: #007bff; letter-spacing: 5px;">${otp}</h1>
        <p>This code will expire in 5 minutes.</p>
      </div>
    `
  };
  await transporter.sendMail(mailOptions);
};

// ==========================================
// ১ & ২. রেজিস্ট্রেশনের জন্য OTP পাঠানো ও ভেরিফাই
// ==========================================

// রেজিস্টার OTP পাঠানো
app.post('/api/send-otp', async (req, res) => {
  try {
    console.log('Received OTP request for email:', req.body.email); // ডিবাগ লাইন
    let { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required' });

    email = email.toLowerCase().trim();
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore[email] = { otp, expiresAt: Date.now() + 5 * 60 * 1000 };

    await sendOtpEmail(email, otp, 'Account Verification OTP');
    res.json({ message: 'OTP sent to your email successfully!' });
  } catch (error) {
    console.error('Error sending register OTP:', error);
    res.status(500).json({ message: 'Failed to send OTP email' });
  }
});

// OTP ভেরিফাই করে রেজিস্টার সম্পন্ন করা
app.post('/api/verify-otp', async (req, res) => {
  try {
    let { name, firm, email, password, region, otp } = req.body;
    email = email.toLowerCase().trim();

    const record = otpStore[email];
    if (!record) return res.status(400).json({ message: 'OTP expired or not requested' });
    if (record.expiresAt < Date.now()) {
      delete otpStore[email];
      return res.status(400).json({ message: 'OTP expired! Request again.' });
    }
    if (record.otp !== otp) return res.status(400).json({ message: 'Invalid OTP code' });

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
    res.status(201).json({ message: 'Account verified & registered successfully!' });
  } catch (error) {
    console.error('Error verifying OTP:', error);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// ==========================================
// ৩. ভুলে যাওয়া পাসওয়ার্ডের জন্য OTP ও রিসেট
// ==========================================

// ফরগট পাসওয়ার্ডের OTP ইমেইলে পাঠানো
app.post('/api/forgot-password-otp', async (req, res) => {
  try {
    let { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required' });

    email = email.toLowerCase().trim();
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'No account found with this email' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore[`reset_${email}`] = { otp, expiresAt: Date.now() + 5 * 60 * 1000 };

    await sendOtpEmail(email, otp, 'Password Reset OTP');
    res.json({ message: 'Password reset OTP sent to your email!' });
  } catch (error) {
    console.error('Error sending reset OTP:', error);
    res.status(500).json({ message: 'Failed to send reset OTP email' });
  }
});

// OTP দিয়ে পাসওয়ার্ড রিসেট করা
app.post('/api/reset-password', async (req, res) => {
  try {
    let { email, otp, newPassword } = req.body;
    email = email.toLowerCase().trim();

    const record = otpStore[`reset_${email}`];
    if (!record) return res.status(400).json({ message: 'OTP expired or not requested' });
    if (record.expiresAt < Date.now()) {
      delete otpStore[`reset_${email}`];
      return res.status(400).json({ message: 'OTP expired!' });
    }
    if (record.otp !== otp) return res.status(400).json({ message: 'Invalid OTP code' });

    delete otpStore[`reset_${email}`];
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await User.findOneAndUpdate({ email }, { password: hashedPassword });
    res.json({ message: 'Password updated successfully! You can login now.' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ message: 'Server error resetting password' });
  }
});

// ==========================================
// ৪. লগইন এবং ইউজার ডাটা (প্রোফাইল, ক্লায়েন্ট, প্ল্যান)
// ==========================================

// লগইন এপিআই
app.post('/api/login', async (req, res) => {
  try {
    let { email, password } = req.body;
    email = email.toLowerCase().trim();

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'secretkey', { expiresIn: '7d' });

    res.json({ 
      token, 
      user: {
        id: user._id,
        name: user.name,
        firm: user.firm,
        email: user.email,
        region: user.region,
        profilePic: user.profilePic || '',
        subscriptionActive: user.subscriptionActive || false,
        clients: user.clients || []
      },
      message: 'Login successful!' 
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server Error during login' });
  }
});

// ডাটা সিঙ্ক করার API
app.get('/api/user-data', async (req, res) => {
  try {
    let { email } = req.query;
    if (!email) return res.status(400).json({ message: 'Email is required' });

    email = email.toLowerCase().trim();
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });
    
    res.json({ 
      user: { 
        name: user.name, 
        firm: user.firm, 
        email: user.email, 
        region: user.region,
        profilePic: user.profilePic || '',
        subscriptionActive: user.subscriptionActive || false 
      },
      clients: user.clients || []
    });
  } catch (err) {
    console.error('Error fetching user data:', err);
    res.status(500).json({ message: 'Server error fetching user data' });
  }
});

// প্রোফাইল আপডেট
app.post('/api/update-profile', async (req, res) => {
  try {
    let { email, profilePic, firm, name } = req.body;
    email = email.toLowerCase().trim();

    const user = await User.findOneAndUpdate(
      { email },
      { $set: { profilePic, firm, name } },
      { new: true }
    );
    
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ message: 'Profile updated successfully', user });
  } catch (err) {
    console.error('Profile update error:', err);
    res.status(500).json({ message: 'Error updating profile' });
  }
});

// ক্লায়েন্ট সেভ করা
app.post('/api/save-client', async (req, res) => {
  try {
    let { email, clientData } = req.body;
    email = email.toLowerCase().trim();

    const user = await User.findOneAndUpdate(
      { email },
      { $push: { clients: clientData } },
      { new: true }
    );
    if (!user) return res.status(404).json({ message: 'User not found' });
    
    res.json({ message: 'Client saved successfully', clients: user.clients });
  } catch (err) {
    console.error('Error saving client:', err);
    res.status(500).json({ message: 'Server error saving client' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));