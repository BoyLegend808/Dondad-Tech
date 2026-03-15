// Netlify Serverless Function - Login
// This replaces the /api/login endpoint for Netlify deployment

const mongoose = require('mongoose');

// MongoDB Connection
let isConnected = false;

async function connectDB() {
  if (isConnected) return;
  
  // Your MongoDB connection string
  const MONGODB_URI = 'mongodb+srv://ugwunekejohn5_db_user:hvu8ud3QFlWojG6o@cluster0.r5kxjyu.mongodb.net/dondad_tech?retryWrites=true&w=majority';
  
  console.log('Attempting to connect to MongoDB...');
  console.log('Connection string (masked):', MONGODB_URI.replace(/\/\/[^@]+@/, '//***:***@'));
  
  if (!MONGODB_URI) {
    throw new Error('MongoDB URI not configured');
  }
  
  try {
    await mongoose.connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 45000,
    });
    isConnected = true;
    console.log('MongoDB connected successfully');
  } catch (error) {
    console.error('MongoDB connection error:', error.message);
    throw new Error('Cannot connect to database: ' + error.message);
  }
}

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, default: 'user' },
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

function verifyPassword(inputPassword, storedPassword) {
  if (storedPassword && !storedPassword.startsWith('$2')) {
    return inputPassword === storedPassword;
  }
  
  try {
    const bcrypt = require('bcryptjs');
    return bcrypt.compareSync(inputPassword, storedPassword);
  } catch (error) {
    console.error('Password verification error:', error);
    return false;
  }
}

function generateToken(user) {
  const JWT_SECRET = process.env.JWT_SECRET || 'default-secret-key-change-in-production';
  const jwt = require('jsonwebtoken');
  
  return jwt.sign(
    { userId: user._id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '24h' }
  );
}

// Rate limiting
const loginAttempts = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000;
const MAX_ATTEMPTS = 5;

function checkRateLimit(ip) {
  const now = Date.now();
  const attempts = loginAttempts.get(ip) || [];
  const validAttempts = attempts.filter(time => now - time < RATE_LIMIT_WINDOW);
  
  if (validAttempts.length >= MAX_ATTEMPTS) {
    return false;
  }
  
  validAttempts.push(now);
  loginAttempts.set(ip, validAttempts);
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
        body: JSON.stringify({ success: false, error: 'Too many login attempts. Please try again later.' })
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

    const email = normalizeEmail(body?.email || '');
    const password = String(body?.password || '').trim();

    if (!email || !password || !isValidEmail(email) || password.length > 200) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ success: false, error: 'Invalid email or password format' })
      };
    }

    const user = await User.findOne({ email }).select('_id name email role password');
    
    if (!user || !verifyPassword(password, user.password)) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ success: false, error: 'Invalid email or password' })
      };
    }

    const sessionToken = generateToken(user);

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        token: sessionToken,
        user: {
          _id: user._id,
          name: user.name,
          email: user.email,
          role: user.role
        }
      })
    };

  } catch (error) {
    console.error('[LOGIN ERROR]', error);
    const errorMessage = error.message || 'Login failed';
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ success: false, error: 'Database error: ' + errorMessage })
    };
  }
};