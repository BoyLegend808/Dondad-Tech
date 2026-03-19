const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const User = require('../models/User'); // Will be imported in server.js

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-change-in-production';

function generateToken(user) {
  return jwt.sign(
    { _id: user._id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '24h' }
  );
}

function verifyToken(token) {
  try {
    return { valid: true, decoded: jwt.verify(token, JWT_SECRET) };
  } catch {
    return { valid: false, decoded: null };
  }
}

function isValidObjectId(id) {
  return mongoose.Types.ObjectId.isValid(String(id || ''));
}

// Middleware: Verify user authentication (JWT or fallback cookie)
const requireAuth = async (req, res, next) => {
  const token = req.cookies?.session || 
               req.headers.authorization?.split(' ')[1];
  
  if (!JWT_SECRET) {
    // Fallback for environments without JWT_SECRET
    const userId = String(req.cookies?.userId || '');
    if (!isValidObjectId(userId)) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    req.user = { _id: userId };
    return next();
  }

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const result = verifyToken(token);
  if (!result.valid) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  req.user = result.decoded;
  next();
};

// Middleware: Admin-only access (verifies role from DB)
const requireAdmin = async (req, res, next) => {
  const token = req.cookies?.session || 
                req.headers.authorization?.split(' ')[1];
  
  if (!JWT_SECRET) {
    // Fallback mode
    const userId = String(req.cookies?.userId || '');
    if (!isValidObjectId(userId)) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    const user = await User.findById(userId).select('role');
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    req.user = { _id: userId, role: user.role };
    return next();
  }

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const result = verifyToken(token);
  if (!result.valid) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  // Double-check admin role in database (security)
  const user = await User.findById(result.decoded._id).select('role');
  if (!user || user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  req.user = { ...result.decoded, dbRole: user.role };
  next();
};

// Middleware: User owns resource (user or admin)
const requireOwnership = async (req, res, next) => {
  const token = req.cookies?.session || 
                req.headers.authorization?.split(' ')[1];
  const requestedUserId = req.params.userId || req.body?.userId;
  
  if (!JWT_SECRET) {
    const userId = String(req.cookies?.userId || '');
    if (!isValidObjectId(userId)) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    if (String(userId) !== String(requestedUserId)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    req.user = { _id: userId };
    return next();
  }

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const result = verifyToken(token);
  if (!result.valid) {
    return res.status(401).json({ error: 'Invalid token' });
  }

  if (result.decoded.role !== 'admin' && 
      result.decoded._id !== requestedUserId) {
    return res.status(403).json({ error: 'Access denied' });
  }

  req.user = result.decoded;
  next();
};

module.exports = {
  requireAuth,
  requireAdmin,
  requireOwnership,
  generateToken,
  verifyToken,
  isValidObjectId
};

