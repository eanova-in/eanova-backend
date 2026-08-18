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

// MongoDB-র সাথে কানেক্ট করা
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB Connected Successfully!'))
  .catch(err => console.log('DB Error:', err));

// ১. সাইন-আপ এপিআই (নতুন ইউজার সেভ করার জন্য)
app.post('/api/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // ইমেইল আগে থেকেই আছে কিনা তা চেক করা
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    // পাসওয়ার্ড নিরাপদ করার জন্য এনক্রিপ্ট/হ্যাশ করা
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully!' });
  } catch (error) {
    res.status(500).json({ message: 'Server Error' });
  }
});

// ২. লগইন এপিআই (পাসওয়ার্ড মিলিয়ে চেক করার জন্য)
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

    res.json({ token, message: 'Login successful!' });
  } catch (error) {
    res.status(500).json({ message: 'Server Error' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));