// Netlify Serverless Function - Register
// This replaces the /api/register endpoint for Netlify deployment

const mongoose = require('mongoose');

// MongoDB Connection
let isConnected = false;

async function connectDB() {
  if (isConnected) return;
  
  const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://ugwunekejohn5_db_user:hvu8ud3QFlWojG6o@cluster0.r5kxjyu.mongodb.net/';
  
  if (!MONGODB_URI) {
    throw new Error('MongoDB URI not configured');
  }
  
  try {
    await mongoose.connect(MONGODB_URI);
    isConnected = true;
    console.log('MongoDB connected successfully');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    throw error;
  }
}

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  phone: String,
  role: { type: String, default: 'user' },
  isEmailVerified: { type: Boolean, default: false },
  verificationToken: String,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.models.User || mongoose.model('User', userSchema);

// Helper Functions
function normalizeEmail(email = "") {
  return email.trim().toLowerCase();
}

function isValidEmail(email = "") {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email));
}

function sanitizeText(text, maxLength) {
  if (!text) return "";
  return String(text).trim().slice(0, maxLength);
}

function hashPassword(password) {
  const bcrypt = require('bcryptjs');
  return bcrypt.hashSync(password, 10);
}

// Rate limiting
const registerAttempts = new Map();
const RATE_LIMIT_WINDOW = 60 * 60 * 1000;
const MAX_ATTEMPTS = 3;

function checkRateLimit(ip) {
  const now = Date.now();
  const attempts = registerAttempts.get(ip) || [];
  const validAttempts = attempts.filter(time => now - time < RATE_LIMIT_WINDOW);
  
  if (validAttempts.length >= MAX_ATTEMPTS) {
    return false;
  }
  
  validAttempts.push(now);
  registerAttempts.set(ip, validAttempts);
  return true;
}

// Main Handler
exports.handler = async (event, context) => {
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ success: false, error: 'Method not allowed' })
    };
  }

  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  try {
    await connectDB();

    const ip = event.headers['x-forwarded-for'] || event.headers['client-ip'] || 'unknown';
    
    if (!checkRateLimit(ip)) {
      return {
        statusCode: 429,
        headers,
        body: JSON.stringify({ success: false, error: 'Too many registration attempts. Please try again later.' })
      };
    }

    let body;
    try {
      body = typeof event.body === 'string' ? JSON.parse(event.body) : event.body;
    } catch (e) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ success: false, error: 'Invalid request body' })
      };
    }

    const name = sanitizeText(body?.name || "", 120);
    const password = String(body?.password || "");
    const phone = sanitizeText(body?.phone || "", 40);
    const email = normalizeEmail(body?.email || "");

    if (!name || !password || !email || !isValidEmail(email)) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ success: false, error: 'Please fill in all required fields correctly' })
      };
    }

    if (password.length < 6 || password.length > 128) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ success: false, error: 'Password must be 6-128 characters' })
      };
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ success: false, error: 'Email already registered' })
      };
    }

    const user = await User.create({
      name,
      email,
      password: hashPassword(password),
      phone,
      role: 'user',
      isEmailVerified: true
    });

    return {
      statusCode: 201,
      headers,
      body: JSON.stringify({
        success: true,
        message: 'Registration successful!',
        user: { id: user._id, name: user.name, email: user.email, role: user.role }
      })
    };

  } catch (error) {
    console.error('[REGISTER ERROR]', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ success: false, error: 'Registration failed: ' + error.message })
    };
  }
};