const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const User = require('./User');

const app = express();
app.use(express.json());
app.use(cors());

// MongoDB কানেকশন
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB Connected Successfully!'))
  .catch(err => console.log('DB Error:', err));

// ১. সাইন-আপ এপিআই (Name, Firm, Region সহ)
app.post('/api/signup', async (req, res) => {
  try {
    const { name, firm, email, password, region } = req.body;
    
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ 
      name, 
      firm, 
      email, 
      password: hashedPassword, 
      region 
    });
    
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully!' });
  } catch (error) {
    res.status(500).json({ message: 'Server Error during signup' });
  }
});

// ২. লগইন এপিআই
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

// ৩. ইউজারের ক্লায়েন্ট লিস্ট ও সাবস্ক্রিপশন ডাটা ফ্রেচ করার এপিআই
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

// ৪. নতুন ক্লায়েন্ট সেভ করার এপিআই
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