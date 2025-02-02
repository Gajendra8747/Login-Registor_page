const express = require('express');
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET; // Replace with your actual secret key
const PORT = process.env.PORT || 5000;

// Middleware
app.use(bodyParser.json());
app.use(cors());

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.log(err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// JWT authentication middleware
function authenticateToken(req, res, next) {
  const token = req.header('Authorization')?.split(' ')[1]; // Bearer <token>
  
  if (!token) return res.status(401).json({ msg: "Access denied" });
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ msg: "Invalid token" });
    req.user = user;
    next();
  });
}

// Register Route
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  const userExists = await User.findOne({ username });
  if (userExists) return res.status(400).json({ msg: "User already exists" });

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = new User({ username, password: hashedPassword });
  await newUser.save();
  
  res.status(201).json({ msg: "User registered successfully" });
});

// Login Route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });
  if (!user) return res.status(400).json({ msg: "User not found" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ msg: "Invalid credentials" });

  const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// Dashboard Route (Protected)
app.get('/dashboard', authenticateToken, (req, res) => {
  res.json({ message: 'Welcome to your dashboard!' });
});

app.get('/' , (req, res) =>{
  res.send("Hello from server!")
}) 

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
