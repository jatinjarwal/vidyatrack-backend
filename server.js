const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const User = require('./models/User');
const Resource = require('./models/Resource');
const { authMiddleware } = require('./middleware/auth');

require('dotenv').config();
const app = express();
app.use(cors({ origin: 'http://localhost:3000', credentials: true }));
app.use(express.json());
app.use(cookieParser());

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error(err));

function generateAccessToken(userId) {
  return jwt.sign({ id: userId }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
}

function generateRefreshToken(userId) {
  return jwt.sign({ id: userId }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
}

// Register
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  const existing = await User.findOne({ email });
  if (existing) return res.status(400).json({ msg: 'User exists' });
  const hashed = await bcrypt.hash(password, 10);
  const newUser = await User.create({ email, password: hashed });
  res.status(201).json({ msg: 'Registered' });
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ msg: 'User not found' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ msg: 'Wrong password' });

  const accessToken = generateAccessToken(user._id);
  const refreshToken = generateRefreshToken(user._id);
  user.refreshToken = refreshToken;
  await user.save();

  res.cookie('refreshToken', refreshToken, { httpOnly: true, path: '/api/refresh' });
  res.json({ accessToken });
});

// Refresh
app.get('/api/refresh', async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, async (err, decoded) => {
    if (err) return res.sendStatus(403);
    const user = await User.findById(decoded.id);
    if (!user || user.refreshToken !== token) return res.sendStatus(403);
    const accessToken = generateAccessToken(user._id);
    res.json({ accessToken });
  });
});

// Logout
app.post('/api/logout', async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.sendStatus(204);
  const user = await User.findOne({ refreshToken: token });
  if (user) {
    user.refreshToken = null;
    await user.save();
  }
  res.clearCookie('refreshToken', { path: '/api/refresh' });
  res.sendStatus(204);
});

// Get resources
app.get('/api/resources', authMiddleware, async (req, res) => {
  const data = await Resource.find({ user: req.user.id });
  res.json(data);
});

// Add resource
app.post('/api/resources', authMiddleware, async (req, res) => {
  const newOne = new Resource({ ...req.body, user: req.user.id });
  const saved = await newOne.save();
  res.status(201).json(saved);
});

// Update resource
app.put('/api/resources/:id', authMiddleware, async (req, res) => {
  const updated = await Resource.findOneAndUpdate(
    { _id: req.params.id, user: req.user.id },
    req.body,
    { new: true }
  );
  if (!updated) return res.sendStatus(404);
  res.json(updated);
});

// Delete resource
app.delete('/api/resources/:id', authMiddleware, async (req, res) => {
  const deleted = await Resource.findOneAndDelete({ _id: req.params.id, user: req.user.id });
  if (!deleted) return res.sendStatus(404);
  res.json({ msg: 'Deleted' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log('Server running on port ' + PORT));