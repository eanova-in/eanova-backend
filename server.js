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

// Transporter তৈরি (Gmail App Password দিয়ে)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// ১. OTP পাঠানোর API
app.post('/api/send-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required' });

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore[email] = { otp, expiresAt: Date.now() + 5 * 60 * 1000 };

    const mailOptions = {
      from: `"Eanova Support" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Eanova - Verification OTP Code',
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #f4f4f4;">
          <h2 style="color: #333;">Welcome to Eanova!</h2>
          <p>Your OTP code for verification is:</p>
          <h1 style="color: #007bff; letter-spacing: 5px;">${otp}</h1>
          <p>This code will expire in 5 minutes.</p>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    res.json({ message: 'OTP sent to email successfully!' });
  } catch (error) {
    console.error('Error sending OTP:', error);
    res.status(500).json({ message: 'Failed to send OTP email' });
  }
});

// ২. OTP যাচাই করে সাইন-আপ সম্পন্ন করার API
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
    res.status(201).json({ message: 'Account verified & registered successfully!' });
  } catch (error) {
    console.error('Error verifying OTP:', error);
    res.status(500).json({ message: 'Server error during OTP verification' });
  }
});

// ৩. লগইন এপিআই
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
      message: 'Login successful!' 
    });
  } catch (error) {
    res.status(500).json({ message: 'Server Error during login' });
  }
});

// ৪. ইউজারের ক্লায়েন্ট লিস্ট ও সাবস্ক্রিপশন ডাটা ফ্রেচ করার এপিআই
app.get('/api/user-data', async (req, res) => {
  try {
    const { email } = req.query;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });
    
    res.json({ 
      user: { name: user.name, firm: user.firm, email: user.email, region: user.region },
      clients: user.clients || [],
      subscriptionActive: user.subscriptionActive || false
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error fetching user data' });
  }
});

// ৫. নতুন ক্লায়েন্ট সেভ করার এপিআই
app.post('/api/save-client', async (req, res) => {
  try {
    const { email, clientData } = req.body;
    const user = await User.findOneAndUpdate(
      { email },
      { $push: { clients: clientData } },
      { new: true }
    );
    if (!user) return res.status(404).json({ message: 'User not found' });
    
    res.json({ message: 'Client saved successfully', clients: user.clients });
  } catch (err) {
    res.status(500).json({ message: 'Server error saving client' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));