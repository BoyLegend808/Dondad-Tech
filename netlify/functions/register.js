// Netlify Serverless Function - Register
// Uses Netlify's built-in PostgreSQL database (Neon)

const { neon } = require('@netlify/neon');
const bcrypt = require('bcryptjs');

async function getDb() {
  const sql = neon(process.env.NETLIFY_DATABASE_URL);
  return sql;
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
    const sql = await getDb();

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

    const name = (body?.name || '').trim().slice(0, 120);
    const password = String(body?.password || '');
    const phone = (body?.phone || '').trim().slice(0, 40);
    const email = (body?.email || '').trim().toLowerCase();

    // Validation
    if (!name || !password || !email) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ success: false, error: 'Please fill in all required fields' })
      };
    }

    if (password.length < 6 || password.length > 128) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ success: false, error: 'Password must be 6-128 characters' })
      };
    }

    // Check if email exists
    const existing = await sql`SELECT id FROM users WHERE email = ${email}`;
    
    if (existing.length > 0) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ success: false, error: 'Email already registered' })
      };
    }

    // Hash password
    const hashedPassword = bcrypt.hashSync(password, 10);

    // Create user - assuming a 'users' table exists
    const result = await sql`
      INSERT INTO users (name, email, password, role)
      VALUES (${name}, ${email}, ${hashedPassword}, 'user')
      RETURNING id, name, email, role
    `;

    const user = result[0];

    return {
      statusCode: 201,
      headers,
      body: JSON.stringify({
        success: true,
        message: 'Registration successful!',
        user: { id: user.id, name: user.name, email: user.email, role: user.role }
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