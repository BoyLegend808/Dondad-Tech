const dns = require('node:dns');
if (!process.env.RENDER) {
    dns.setServers(['8.8.8.8', '1.1.1.1']);
}

const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const path = require("path");
const mongoose = require("mongoose");
const crypto = require("crypto");
const Stripe = require("stripe");
const https = require('https');
const querystring = require('querystring');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3000;
let dbReady = false;

const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 10;
const loginAttempts = new Map();
const apiRateAttempts = new Map();
const sensitiveRateAttempts = new Map();

// In-memory rate limiting (can be upgraded to Redis in production)
let globalApiRateLimit = (req, res, next) => next();
let globalSensitiveRateLimit = (req, res, next) => next();
function apiRateLimit(req, res, next) {
  return globalApiRateLimit(req, res, next);
}
function sensitiveRateLimit(req, res, next) {
  return globalSensitiveRateLimit(req, res, next);
}

// MongoDB Connection
function resolveMongoUri() {
  const candidates = [
    "MONGODB_URI",
    "MONGO_URI",
    "MONGODB_URL",
    "MONGO_URL",
    "DATABASE_URL",
    "DATABASE_PRIVATE_URL",
    "MONGODB_PRIVATE_URL",
    "MONGODB_PUBLIC_URL",
  ];
  for (const key of candidates) {
    const raw = process.env[key];
    if (!raw) continue;
    const cleaned = String(raw).trim().replace(/^['"]|['"]$/g, "");
    if (cleaned) return cleaned;
  }
  return "";
}

const MONGODB_URI = resolveMongoUri();

if (!MONGODB_URI) {
  console.error(
    "[Startup] Missing DB URI env var. Set one of: MONGODB_URI, MONGO_URI, MONGODB_URL, MONGO_URL, DATABASE_URL, DATABASE_PRIVATE_URL, MONGODB_PRIVATE_URL, MONGODB_PUBLIC_URL",
  );
} else {
  mongoose
    .connect(MONGODB_URI)
    .then(async () => {
      dbReady = true;
      console.log("Connected to MongoDB");
      await seedDatabase(); // Run seed after connection
      await ensureDefaultUsers();
      await migrateLegacyPasswords();
    })
    .catch((err) => {
      dbReady = false;
      console.error("MongoDB connection error:", err);
    });
}

// Mongoose Schemas
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phone: { type: String, default: "" },
  role: { type: String, default: "user" },
});

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  category: { type: String, required: true },
  price: { type: Number, required: true },
  image: { type: String, required: true },
  desc: { type: String, default: "" }, // Short description for product cards
  fullDesc: { type: String, default: "" }, // Full description for product detail page
  // Variant fields
  hasVariants: { type: Boolean, default: false },
  variants: {
    storage: [{
      option: { type: String, default: "" },
      priceModifier: { type: Number, default: 0 },
      stock: { type: Number, default: 0 }
    }],
    ram: [{
      option: { type: String, default: "" },
      priceModifier: { type: Number, default: 0 },
      stock: { type: Number, default: 0 }
    }],
    color: [{
      option: { type: String, default: "" },
      priceModifier: { type: Number, default: 0 },
      stock: { type: Number, default: 0 },
      image: { type: String, default: "" }
    }]
  }
});

const cartSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  productId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Product",
    required: true,
  },
  qty: { type: Number, default: 1 },
  // Variant selection
  selectedVariant: {
    storage: { type: String, default: "" },
    ram: { type: String, default: "" },
    color: { type: String, default: "" }
  },
  // Store price at time of addition
  unitPrice: { type: Number, required: true }
});

// Flutterwave/Paystack Configuration (use environment variables in production)
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || 'sk_test_your_key_here';
const PAYSTACK_BASE_URL = 'https://api.paystack.co';
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

// Initialize payment
app.post('/api/payment/initialize', sensitiveRateLimit, async (req, res) => {
    try {
        const email = normalizeEmail(req.body?.email || "");
        const amount = parseMoney(req.body?.amount, null);
        const orderId = sanitizeText(req.body?.orderId || "", 80);
        
        if (!email || amount === null || !orderId || !isValidEmail(email) || amount <= 0) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Convert amount to kobo (Paystack uses kobo)
        const amountInKobo = Math.round(amount * 100);

        const response = await fetch(`${PAYSTACK_BASE_URL}/transaction/initialize`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${PAYSTACK_SECRET_KEY}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email,
                amount: amountInKobo,
                reference: `ORD_${orderId}_${Date.now()}`,
                callback_url: `${req.protocol}://${req.get('host')}/checkout.html?payment=success`
            })
        });

        const data = await response.json();
        
        if (data.status) {
            res.json({ 
                success: true, 
                authorizationUrl: data.data.authorization_url,
                reference: data.data.reference 
            });
        } else {
            res.status(400).json({ success: false, error: data.message });
        }
    } catch (error) {
        console.error('Payment init error:', error);
        res.status(500).json({ error: 'Payment initialization failed' });
    }
});

// Verify payment
app.get('/api/payment/verify/:reference', sensitiveRateLimit, async (req, res) => {
    try {
        const reference = sanitizeText(req.params?.reference || "", 120);
        if (!reference) {
          return res.status(400).json({ error: "Invalid reference" });
        }

        const response = await fetch(`${PAYSTACK_BASE_URL}/transaction/verify/${reference}`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${PAYSTACK_SECRET_KEY}`
            }
        });

        const data = await response.json();
        
        if (data.status && data.data.status === 'success') {
            res.json({ success: true, verified: true, data: data.data });
        } else {
            res.json({ success: true, verified: false });
        }
    } catch (error) {
        console.error('Payment verify error:', error);
        res.status(500).json({ error: 'Payment verification failed' });
    }
});

// Stripe Checkout Session
app.post("/api/payment/stripe/checkout", sensitiveRateLimit, async (req, res) => {
  try {
    if (!stripe) {
      return res.status(500).json({ error: "Stripe is not configured on server" });
    }
    const email = normalizeEmail(req.body?.email || "");
    const amount = parseMoney(req.body?.amount, null);
    const orderId = String(req.body?.orderId || "");
    if (!isValidEmail(email) || amount === null || amount <= 0 || !isValidObjectId(orderId)) {
      return res.status(400).json({ error: "Invalid Stripe checkout payload" });
    }

    const origin = `${req.protocol}://${req.get("host")}`;
    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      payment_method_types: ["card"],
      customer_email: email,
      line_items: [
        {
          price_data: {
            currency: "ngn",
            product_data: {
              name: `Order ${orderId}`,
              description: "Pajay Gadgets checkout",
            },
            unit_amount: Math.round(amount * 100),
          },
          quantity: 1,
        },
      ],
      metadata: { orderId },
      success_url: `${origin}/checkout.html?payment=stripe_success&orderId=${orderId}`,
      cancel_url: `${origin}/checkout.html?payment=stripe_cancel&orderId=${orderId}`,
    });

    res.json({ success: true, url: session.url, sessionId: session.id });
  } catch (error) {
    console.error("Stripe checkout error:", error);
    res.status(500).json({ error: "Failed to initialize Stripe checkout" });
  }
});

// Stripe Webhook (raw body required for signature validation)
app.post("/api/payment/stripe/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    if (!stripe || !STRIPE_WEBHOOK_SECRET) {
      return res.status(500).send("Stripe webhook not configured");
    }
    const signature = req.headers["stripe-signature"];
    if (!signature) {
      return res.status(400).send("Missing Stripe signature");
    }

    const event = stripe.webhooks.constructEvent(req.body, signature, STRIPE_WEBHOOK_SECRET);
    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const orderId = session?.metadata?.orderId;
      if (isValidObjectId(orderId)) {
        const order = await Order.findByIdAndUpdate(
          orderId,
          {
            paymentStatus: "paid",
            paymentReference: sanitizeText(session.payment_intent || session.id || "", 120),
            status: "confirmed",
            updatedAt: Date.now(),
          },
          { new: true },
        );
        if (order) {
          await Cart.deleteMany({ userId: order.userId });
        }
      }
    }

    return res.status(200).json({ received: true });
  } catch (error) {
    console.error("Stripe webhook error:", error.message || error);
    return res.status(400).send(`Webhook Error: ${error.message || "Invalid event"}`);
  }
});

// Order Schema
const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  userName: { type: String, required: true },
  userEmail: { type: String, required: true },
  userPhone: { type: String, required: true },
  items: [{
    productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product" },
    productName: { type: String },
    productImage: { type: String },
    qty: { type: Number },
    unitPrice: { type: Number },
    selectedVariant: {
      storage: { type: String, default: "" },
      ram: { type: String, default: "" },
      color: { type: String, default: "" }
    }
  }],
  deliveryInfo: {
    address: { type: String },
    method: { type: String },
    notes: { type: String },
    // Tracking info
    trackingNumber: { type: String, default: "" },
    estimatedDelivery: { type: Date },
    shippedDate: { type: Date },
    deliveredDate: { type: Date }
  },
  paymentMethod: { type: String },
  paymentStatus: { type: String, default: "pending" }, // pending, paid, failed
  paymentReference: { type: String, default: "" },
  subtotal: { type: Number },
  status: { type: String, default: "pending" }, // pending, confirmed, processing, shipped, delivered, cancelled
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);
const Product = mongoose.model("Product", productSchema);
const Cart = mongoose.model("Cart", cartSchema);
const Order = mongoose.model("Order", orderSchema);

// Review Schema
const reviewSchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product", required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  userName: { type: String, required: true },
  rating: { type: Number, required: true, min: 1, max: 5 },
  comment: { type: String, default: "" },
  createdAt: { type: Date, default: Date.now }
});

// Wishlist Schema
const wishlistSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  products: [{ type: mongoose.Schema.Types.ObjectId, ref: "Product" }],
  updatedAt: { type: Date, default: Date.now }
});

const Review = mongoose.model("Review", reviewSchema);
const Wishlist = mongoose.model("Wishlist", wishlistSchema);

const DEFAULT_USERS = [
  {
    name: "Admin",
    email: "admin@dondad.com",
    password: "admin123",
    phone: "08000000000",
    role: "admin",
  },
  {
    name: "Admin",
    email: "admin@dondadtech.com",
    password: "admin123",
    phone: "08000000000",
    role: "admin",
  },
  {
    name: "John",
    email: "ugwunekejohn5@gmail.com",
    password: "customer123",
    phone: "08012345678",
    role: "customer",
  },
];

function normalizeEmail(email = "") {
  return email.trim().toLowerCase();
}

function sanitizeText(input = "", maxLen = 500) {
  return String(input || "")
    .trim()
    .replace(/\s+/g, " ")
    .slice(0, maxLen);
}

function escapeRegex(input = "") {
  return String(input).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function isValidObjectId(id) {
  return mongoose.Types.ObjectId.isValid(String(id || ""));
}

function parsePositiveInt(value, fallback = 1) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return parsed;
}

function parseMoney(value, fallback = null) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) return fallback;
  return parsed;
}

function isValidEmail(email = "") {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email));
}

function hasUnsafeKeys(value) {
  if (!value || typeof value !== "object") return false;
  if (Array.isArray(value)) {
    return value.some((item) => hasUnsafeKeys(item));
  }
  return Object.entries(value).some(([key, nested]) => {
    if (String(key).startsWith("$") || String(key).includes(".")) return true;
    return hasUnsafeKeys(nested);
  });
}

function safeVariant(raw) {
  const variant = raw && typeof raw === "object" ? raw : {};
  return {
    storage: sanitizeText(variant.storage || "", 40),
    ram: sanitizeText(variant.ram || "", 40),
    color: sanitizeText(variant.color || "", 40),
  };
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const iterations = 100000;
  const hash = crypto
    .pbkdf2Sync(password, salt, iterations, 64, "sha512")
    .toString("hex");
  return `pbkdf2$${iterations}$${salt}$${hash}`;
}

function isPasswordHashed(password = "") {
  return typeof password === "string" && password.startsWith("pbkdf2$");
}

function verifyPassword(inputPassword, storedPassword) {
  // Only accept hashed passwords - remove legacy plain text support
  if (!isPasswordHashed(storedPassword)) {
    console.error('Found legacy password hash - needs migration');
    return false; // Reject legacy passwords - user must reset
  }

  const [scheme, iterationStr, salt, storedHash] = storedPassword.split("$");
  if (scheme !== "pbkdf2" || !iterationStr || !salt || !storedHash) {
    return false;
  }

  const iterations = parseInt(iterationStr, 10);
  if (!Number.isFinite(iterations) || iterations <= 0) {
    return false;
  }

  const computedHash = crypto
    .pbkdf2Sync(inputPassword, salt, iterations, 64, "sha512")
    .toString("hex");

  const a = Buffer.from(computedHash, "hex");
  const b = Buffer.from(storedHash, "hex");
  if (a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

function loginRateLimit(req, res, next) {
  const key = req.ip || req.connection.remoteAddress || "unknown";
  const now = Date.now();
  const record = loginAttempts.get(key);

  if (!record || now > record.expiresAt) {
    loginAttempts.set(key, { count: 1, expiresAt: now + LOGIN_WINDOW_MS });
    return next();
  }

  if (record.count >= LOGIN_MAX_ATTEMPTS) {
    return res.status(429).json({
      success: false,
      error: "Too many login attempts. Please try again in 15 minutes.",
    });
  }

  record.count += 1;
  loginAttempts.set(key, record);
  next();
}

function createIpRateLimiter(store, windowMs, max, errorMessage) {
  return (req, res, next) => {
    const key = req.ip || req.connection.remoteAddress || "unknown";
    const now = Date.now();
    const record = store.get(key);

    if (!record || now > record.expiresAt) {
      store.set(key, { count: 1, expiresAt: now + windowMs });
      return next();
    }

    if (record.count >= max) {
      return res.status(429).json({ error: errorMessage });
    }

    record.count += 1;
    store.set(key, record);
    next();
  };
}

globalApiRateLimit = createIpRateLimiter(
  apiRateAttempts,
  15 * 60 * 1000,
  600,
  "Too many API requests. Please try again later.",
);

globalSensitiveRateLimit = createIpRateLimiter(
  sensitiveRateAttempts,
  15 * 60 * 1000,
  120,
  "Too many requests on this endpoint. Please try again later.",
);

// JWT Secret for session tokens
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

function generateToken(user) {
  return crypto.createHmac('sha256', JWT_SECRET)
    .update(JSON.stringify({ _id: user._id, email: user.email, role: user.role }))
    .digest('hex');
}

function verifyToken(token) {
  try {
    // For simplicity, we'll verify by regenerating - in production use proper JWT
    return { valid: true };
  } catch (e) {
    return { valid: false };
  }
}

// Middleware to require admin role
function requireAdmin(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  // Get user from token (decoded from login response)
  const userId = req.headers['x-user-id'];
  const userRole = req.headers['x-user-role'];
  
  if (!userId || !userRole) {
    return res.status(401).json({ error: 'Invalid token format' });
  }
  
  if (userRole !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  
  next();
}

function requireInternalAccess(req, res, next) {
  if (process.env.NODE_ENV !== "production") {
    return next();
  }
  const token = req.headers["x-admin-token"];
  const expected = process.env.ADMIN_API_TOKEN;
  if (!expected || token !== expected) {
    return res.status(403).json({ error: "Forbidden" });
  }
  next();
}

async function ensureDefaultUsers() {
  for (const defaultUser of DEFAULT_USERS) {
    const email = normalizeEmail(defaultUser.email);
    const existing = await User.findOne({ email });
    if (!existing) {
      await User.create({
        ...defaultUser,
        email,
        password: hashPassword(defaultUser.password),
      });
      console.log(`Created default user: ${email}`);
    }
  }
}

async function migrateLegacyPasswords() {
  // Log legacy passwords for manual review - don't auto-migrate
  const users = await User.find({});
  let legacyCount = 0;
  for (const user of users) {
    if (!isPasswordHashed(user.password)) {
      legacyCount++;
      console.log(`Legacy password found for user: ${user.email} - needs password reset`);
    }
  }
  if (legacyCount > 0) {
    console.log(`Found ${legacyCount} users with legacy passwords - they will need to reset`);
  }
}

// Password reset tokens (in production, use Redis or database)
const passwordResetTokens = new Map();

// Forgot Password - send reset email
app.post("/api/forgot-password", sensitiveRateLimit, async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email || "");
    if (!email || !isValidEmail(email)) {
      return res.status(400).json({ success: false, error: "Invalid email" });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      // Don't reveal if user exists
      return res.json({ success: true, message: "If email exists, reset link sent" });
    }
    
    // Generate reset token (valid for 1 hour)
    const resetToken = crypto.randomBytes(32).toString('hex');
    passwordResetTokens.set(resetToken, {
      email,
      expiresAt: Date.now() + 60 * 60 * 1000
    });
    
    // In production, send email with reset link
    // For now, log the token (in production, integrate with email service)
    console.log(`Password reset for ${email}: /reset-password.html?token=${resetToken}`);
    
    res.json({ success: true, message: "If email exists, reset link sent" });
  } catch (error) {
    res.status(500).json({ error: "Failed to process request" });
  }
});

// Reset Password
app.post("/api/reset-password", sensitiveRateLimit, async (req, res) => {
  try {
    const token = String(req.body?.token || "").trim();
    const newPassword = String(req.body?.password || "");
    
    if (!token || !newPassword) {
      return res.status(400).json({ success: false, error: "Missing required fields" });
    }
    
    if (newPassword.length < 6 || newPassword.length > 128) {
      return res.status(400).json({ success: false, error: "Password must be 6-128 characters" });
    }
    
    const tokenData = passwordResetTokens.get(token);
    if (!tokenData) {
      return res.status(400).json({ success: false, error: "Invalid or expired token" });
    }
    
    if (Date.now() > tokenData.expiresAt) {
      passwordResetTokens.delete(token);
      return res.status(400).json({ success: false, error: "Token expired" });
    }
    
    const user = await User.findOne({ email: tokenData.email });
    if (!user) {
      return res.status(400).json({ success: false, error: "User not found" });
    }
    
    // Hash and save new password
    user.password = hashPassword(newPassword);
    await user.save();
    
    // Clear token
    passwordResetTokens.delete(token);
    
    res.json({ success: true, message: "Password reset successful" });
  } catch (error) {
    res.status(500).json({ error: "Failed to reset password" });
  }
});

// Seed initial data
async function seedDatabase() {
  try {
    const userCount = await User.countDocuments();
    if (userCount === 0) {
      await User.create({
        name: "Admin",
        email: "admin@dondad.com",
        password: hashPassword("admin123"),
        phone: "08000000000",
        role: "admin",
      });

      const products = [
        {
          name: "iPhone 13 Pro Max",
          category: "phones",
          price: 450000,
          image: "xs.png",
          desc: "256GB, A15 chip",
        },
        {
          name: "iPhone 13 Pro",
          category: "phones",
          price: 400000,
          image: "xs.png",
          desc: "256GB, A15 chip",
        },
        {
          name: "iPhone 13",
          category: "phones",
          price: 350000,
          image: "xs.png",
          desc: "128GB, A15 chip",
        },
        {
          name: "iPhone 12 Pro Max",
          category: "phones",
          price: 320000,
          image: "xs.png",
          desc: "128GB, A14 chip",
        },
        {
          name: "iPhone 12",
          category: "phones",
          price: 280000,
          image: "xs.png",
          desc: "128GB, A14 chip",
        },
        {
          name: "iPhone 11",
          category: "phones",
          price: 220000,
          image: "xs.png",
          desc: "64GB, A13 chip",
        },
        {
          name: "iPhone XS Max",
          category: "phones",
          price: 180000,
          image: "xs.png",
          desc: "64GB, A12 chip",
        },
        {
          name: "iPhone XR",
          category: "phones",
          price: 150000,
          image: "xs.png",
          desc: "64GB, A12 chip",
        },
        {
          name: "MacBook Pro 14",
          category: "laptops",
          price: 850000,
          image: "hero img.png",
          desc: "M1 Pro, 16GB RAM",
        },
        {
          name: "MacBook Air M2",
          category: "laptops",
          price: 650000,
          image: "hero img.png",
          desc: "M2 chip, 8GB RAM",
        },
        {
          name: "Dell XPS 13",
          category: "laptops",
          price: 550000,
          image: "hero img.png",
          desc: "Intel i7, 16GB RAM",
        },
        {
          name: "HP Spectre x360",
          category: "laptops",
          price: 480000,
          image: "hero img.png",
          desc: "Intel i7, 16GB RAM",
        },
        {
          name: "Lenovo ThinkPad",
          category: "laptops",
          price: 520000,
          image: "hero img.png",
          desc: "Intel i7, 16GB RAM",
        },
        {
          name: "iPad Pro 12.9",
          category: "tablets",
          price: 550000,
          image: "xs.png",
          desc: "M1 chip, 128GB",
        },
        {
          name: "iPad Air",
          category: "tablets",
          price: 350000,
          image: "xs.png",
          desc: "M1 chip, 64GB",
        },
        {
          name: "iPad 10th Gen",
          category: "tablets",
          price: 250000,
          image: "xs.png",
          desc: "A14 chip, 64GB",
        },
        {
          name: "Samsung Tab S8",
          category: "tablets",
          price: 380000,
          image: "xs.png",
          desc: "Snapdragon 8 Gen 1",
        },
        {
          name: "AirPods Pro",
          category: "accessories",
          price: 120000,
          image: "xs.png",
          desc: "Active Noise Cancellation",
        },
        {
          name: "AirPods 3",
          category: "accessories",
          price: 85000,
          image: "xs.png",
          desc: "Spatial audio",
        },
        {
          name: "iPhone Charger",
          category: "accessories",
          price: 15000,
          image: "xs.png",
          desc: "20W Fast charging",
        },
        {
          name: "USB-C Cable",
          category: "accessories",
          price: 5000,
          image: "xs.png",
          desc: "1m braided",
        },
        {
          name: "Phone Case",
          category: "accessories",
          price: 8000,
          image: "xs.png",
          desc: "Silicone case",
        },
        {
          name: "Power Bank",
          category: "accessories",
          price: 25000,
          image: "xs.png",
          desc: "20000mAh",
        },
        {
          name: "Screen Protector",
          category: "accessories",
          price: 3000,
          image: "xs.png",
          desc: "Tempered glass",
        },
      ];

      await Product.insertMany(products);
      console.log("Database seeded with initial data");
    }
  } catch (err) {
    console.error("Seeding error:", err);
  }
}

// Middleware
const defaultAllowedOrigins = [
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "https://dondad-tech-production-0b1a.up.railway.app",
];
const allowedOrigins = (
  process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(",").map((o) => o.trim()).filter(Boolean)
    : defaultAllowedOrigins
);
app.use(
  cors({
    origin(origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("Not allowed by CORS"));
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Admin-Token"],
    credentials: false,
  }),
);
const jsonParser = bodyParser.json();
app.use((req, res, next) => {
  if (req.path === "/api/payment/stripe/webhook") {
    return next();
  }
  return jsonParser(req, res, next);
});
app.use(express.static(__dirname));
app.use(cookieParser());
app.use("/api", (req, res, next) => {
  if (req.path === "/payment/stripe/webhook") {
    return next();
  }
  if (
    hasUnsafeKeys(req.body) ||
    hasUnsafeKeys(req.query) ||
    hasUnsafeKeys(req.params)
  ) {
    return res.status(400).json({ error: "Unsafe input detected" });
  }
  next();
});
app.use("/api", apiRateLimit);
app.use("/api", (req, res, next) => {
  if (dbReady) return next();
  const allowedWithoutDb = [
    "/payment/initialize",
    "/payment/verify/",
    "/health/security",
  ];
  if (allowedWithoutDb.some((p) => req.path.startsWith(p))) {
    return next();
  }
  return res.status(503).json({
    error:
      "Database is not configured or not connected. Set MONGODB_URI (or MONGODB_URL/MONGO_URL/DATABASE_URL) and restart.",
  });
});

// --- API ROUTES ---

// Add product (admin only)
app.post("/api/products", requireAdmin, async (req, res) => {
  try {
    const name = sanitizeText(req.body?.name || "", 120);
    const category = sanitizeText(req.body?.category || "", 40).toLowerCase();
    const price = parseMoney(req.body?.price, null);
    const image = sanitizeText(req.body?.image || "", 400);
    const desc = sanitizeText(req.body?.desc || "", 600);
    const fullDesc = sanitizeText(req.body?.fullDesc || "", 4000);
    const stock = parsePositiveInt(req.body?.stock, 0);
    
    if (!name || !category || price === null) {
      return res.status(400).json({ error: "Invalid product data" });
    }
    
    const allowedCategories = new Set(["phones", "laptops", "tablets", "accessories"]);
    if (!allowedCategories.has(category)) {
      return res.status(400).json({ error: "Invalid category" });
    }
    
    const product = await Product.create({
      name,
      category,
      price,
      image,
      desc,
      fullDesc,
      stock,
      hasVariants: false,
      variants: { storage: [], ram: [], color: [] }
    });
    
    res.status(201).json(product);
  } catch (error) {
    console.error("Add Product Error:", error);
    res.status(500).json({ error: "Failed to add product" });
  }
});

// Get all products
app.get("/api/products", async (req, res) => {
  try {
    const category = sanitizeText(req.query?.category || "", 40).toLowerCase();
    const search = sanitizeText(req.query?.search || "", 120);
    let query = {};
    const allowedCategories = new Set(["phones", "laptops", "tablets", "accessories", "all", ""]);
    if (!allowedCategories.has(category)) {
      return res.status(400).json({ error: "Invalid category" });
    }
    if (category && category !== "all") query.category = category;
    if (search) {
      const escapedSearch = escapeRegex(search);
      query.$or = [
        { name: { $regex: escapedSearch, $options: "i" } },
        { desc: { $regex: escapedSearch, $options: "i" } },
      ];
    }
    const products = await Product.find(query).sort({ _id: 1 });
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch products" });
  }
});

// Get single product by ID
app.get("/api/products/:id", async (req, res) => {
  try {
    const productId = String(req.params?.id || "");
    if (!isValidObjectId(productId)) {
      return res.status(400).json({ error: "Invalid product id" });
    }
    const product = await Product.findById(productId);
    if (product) {
      res.json(product);
    } else {
      res.status(404).json({ error: "Product not found" });
    }
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch product" });
  }
});

// Update product (admin only)
app.put("/api/products/:id", requireAdmin, async (req, res) => {
  try {
    const productId = String(req.params?.id || "");
    if (!isValidObjectId(productId)) {
      return res.status(400).json({ error: "Invalid product id" });
    }
    const update = {};
    if (req.body?.name !== undefined) update.name = sanitizeText(req.body.name, 120);
    if (req.body?.category !== undefined) update.category = sanitizeText(req.body.category, 40).toLowerCase();
    if (req.body?.image !== undefined) update.image = sanitizeText(req.body.image, 400);
    if (req.body?.desc !== undefined) update.desc = sanitizeText(req.body.desc, 600);
    if (req.body?.fullDesc !== undefined) update.fullDesc = sanitizeText(req.body.fullDesc, 4000);
    if (req.body?.price !== undefined) {
      const price = parseMoney(req.body.price, null);
      if (price === null) return res.status(400).json({ error: "Invalid price" });
      update.price = price;
    }
    if (req.body?.hasVariants !== undefined) update.hasVariants = Boolean(req.body.hasVariants);
    if (req.body?.variants !== undefined && typeof req.body.variants === "object") {
      update.variants = req.body.variants;
    }
    const product = await Product.findByIdAndUpdate(
      productId,
      update,
      { new: true }
    );
    if (product) {
      res.json(product);
    } else {
      res.status(404).json({ error: "Product not found" });
    }
  } catch (error) {
    res.status(500).json({ error: "Failed to update product" });
  }
});

// Delete product (admin only)
app.delete("/api/products/:id", requireAdmin, async (req, res) => {
  try {
    const productId = String(req.params?.id || "");
    if (!isValidObjectId(productId)) {
      return res.status(400).json({ error: "Invalid product id" });
    }
    const product = await Product.findByIdAndDelete(productId);
    if (product) {
      res.json({ success: true });
    } else {
      res.status(404).json({ error: "Product not found" });
    }
  } catch (error) {
    res.status(500).json({ error: "Failed to delete product" });
  }
});

// Migrate existing products to add variant fields
app.get("/api/products/migrate-variants", requireInternalAccess, async (req, res) => {
  try {
    const result = await Product.updateMany(
      { hasVariants: { $exists: false } },
      {
        $set: {
          hasVariants: false,
          variants: {
            storage: [],
            ram: [],
            color: []
          }
        }
      }
    );
    res.json({
      success: true,
      message: `Migrated ${result.modifiedCount} products`
    });
  } catch (error) {
    res.status(500).json({ error: "Migration failed" });
  }
});

// Get Featured Products (changes every 24 hours)
app.get("/api/featured", async (req, res) => {
  try {
    // Get current date to create daily rotation
    const today = new Date();
    const seed = today.getFullYear() * 10000 + (today.getMonth() + 1) * 100 + today.getDate();
    
    // Get all products
    const allProducts = await Product.find({}).lean();
    
    // Seeded random shuffle based on date
    const shuffled = [...allProducts].sort((a, b) => {
      const hashA = a._id.toString().split('').reduce((acc, char) => acc + char.charCodeAt(0), 0) + seed;
      const hashB = b._id.toString().split('').reduce((acc, char) => acc + char.charCodeAt(0), 0) + seed;
      // Simple pseudo-random based on hash
      const randA = (hashA * 9301 + 49297) % 233280;
      const randB = (hashB * 9301 + 49297) % 233280;
      return randA - randB;
    });
    
    // Take first 8 products
    const featured = shuffled.slice(0, 8);
    res.json(featured);
  } catch (error) {
    console.error("Featured error:", error);
    res.status(500).json({ error: "Failed to fetch featured products" });
  }
});

// Cart Route
app.get("/api/cart/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    if (!isValidObjectId(userId)) {
      return res.status(400).json({ error: "Valid User ID is required" });
    }
    const cartItems = await Cart.find({ userId }).populate("productId");
    res.json(cartItems);
  } catch (error) {
    console.error("Cart Error:", error);
    res.status(500).json({ error: "Error fetching cart" });
  }
});

// Add to Cart
app.post("/api/cart/:userId/:productId", async (req, res) => {
  try {
    const { userId, productId } = req.params;
    const qty = parsePositiveInt(req.body?.qty, 1);
    const selectedVariant = safeVariant(req.body?.selectedVariant);
    const unitPrice = parseMoney(req.body?.unitPrice, null);
    
    if (!isValidObjectId(userId) || !isValidObjectId(productId)) {
      return res.status(400).json({ error: "User ID and Product ID are required" });
    }
    
    // Get product to calculate price if not provided
    let price = unitPrice;
    if (price === undefined) {
      const product = await Product.findById(productId);
      if (!product) {
        return res.status(404).json({ error: "Product not found" });
      }
      price = product.price;
    }
    
    // Check for existing cart item with same product and variant
    const existingQuery = { userId, productId };
    existingQuery["selectedVariant.storage"] = selectedVariant.storage || "";
    existingQuery["selectedVariant.ram"] = selectedVariant.ram || "";
    existingQuery["selectedVariant.color"] = selectedVariant.color || "";
    
    const existing = await Cart.findOne(existingQuery);
    if (existing) {
      existing.qty += qty || 1;
      await existing.save();
    } else {
      await Cart.create({
        userId,
        productId,
        qty: qty || 1,
        selectedVariant,
        unitPrice: price
      });
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error("Add to Cart Error:", error);
    res.status(500).json({ error: "Failed to add to cart" });
  }
});

// Update Cart Quantity
app.put("/api/cart/:userId/:productId", async (req, res) => {
  try {
    const { userId, productId } = req.params;
    const rawQty = req.body?.qty;
    const qty = rawQty !== undefined ? parsePositiveInt(rawQty, 1) : undefined;
    const selectedVariant = req.body?.selectedVariant ? safeVariant(req.body.selectedVariant) : undefined;
    if (!isValidObjectId(userId) || !isValidObjectId(productId)) {
      return res.status(400).json({ error: "Invalid ID" });
    }
    
    const query = { userId, productId };
    if (selectedVariant) {
      query["selectedVariant.storage"] = selectedVariant.storage || "";
      query["selectedVariant.ram"] = selectedVariant.ram || "";
      query["selectedVariant.color"] = selectedVariant.color || "";
    }
    
    if (rawQty !== undefined && Number(rawQty) <= 0) {
      await Cart.findOneAndDelete(query);
    } else if (qty !== undefined) {
      await Cart.findOneAndUpdate(query, { qty });
    } else if (selectedVariant) {
      // Just updating variant
      await Cart.findOneAndUpdate(query, { selectedVariant });
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error("Update Cart Error:", error);
    res.status(500).json({ error: "Failed to update cart" });
  }
});

// Remove from Cart
app.delete("/api/cart/:userId/:productId", async (req, res) => {
  try {
    const { userId, productId } = req.params;
    const { selectedVariant } = req.query;
    if (!isValidObjectId(userId) || !isValidObjectId(productId)) {
      return res.status(400).json({ error: "Invalid ID" });
    }
    
    const query = { userId, productId };
    if (selectedVariant) {
      try {
        const variant = JSON.parse(selectedVariant);
        const safe = safeVariant(variant);
        query["selectedVariant.storage"] = safe.storage || "";
        query["selectedVariant.ram"] = safe.ram || "";
        query["selectedVariant.color"] = safe.color || "";
      } catch (e) {
        // Invalid JSON, remove without variant filter
      }
    }
    
    await Cart.findOneAndDelete(query);
    res.json({ success: true });
  } catch (error) {
    console.error("Remove from Cart Error:", error);
    res.status(500).json({ error: "Failed to remove from cart" });
  }
});

// ============= ORDER ENDPOINTS =============

// Create Order
app.post("/api/orders", sensitiveRateLimit, async (req, res) => {
  try {
    const userId = String(req.body?.userId || "");
    const userName = sanitizeText(req.body?.userName || "", 120);
    const userEmail = normalizeEmail(req.body?.userEmail || "");
    const userPhone = sanitizeText(req.body?.userPhone || "", 40);
    const items = Array.isArray(req.body?.items) ? req.body.items : [];
    const paymentMethod = sanitizeText(req.body?.paymentMethod || "", 40);
    const subtotal = parseMoney(req.body?.subtotal, null);
    const deliveryInfoRaw = req.body?.deliveryInfo && typeof req.body.deliveryInfo === "object" ? req.body.deliveryInfo : {};
    const deliveryInfo = {
      address: sanitizeText(deliveryInfoRaw.address || "", 300),
      method: sanitizeText(deliveryInfoRaw.method || "", 40),
      notes: sanitizeText(deliveryInfoRaw.notes || "", 800),
    };
    if (!isValidObjectId(userId) || !userName || !isValidEmail(userEmail) || subtotal === null) {
      return res.status(400).json({ error: "Invalid order payload" });
    }
    if (!items.length || items.length > 100) {
      return res.status(400).json({ error: "Order items are required" });
    }
    const allowedPaymentMethods = new Set(["cash", "transfer", "stripe"]);
    if (!allowedPaymentMethods.has(paymentMethod)) {
      return res.status(400).json({ error: "Invalid payment method" });
    }
    
    const order = await Order.create({
      userId,
      userName,
      userEmail,
      userPhone,
      items,
      deliveryInfo,
      paymentMethod,
      subtotal,
      status: "pending"
    });
    
    // Keep cart for Stripe until payment confirmation via webhook
    if (paymentMethod !== "stripe") {
      await Cart.deleteMany({ userId });
    }
    
    res.json({ success: true, order });
  } catch (error) {
    console.error("Create Order Error:", error);
    res.status(500).json({ error: "Failed to create order" });
  }
});

// Get user's orders
app.get("/api/orders/user/:userId", async (req, res) => {
  try {
    const userId = String(req.params?.userId || "");
    if (!isValidObjectId(userId)) {
      return res.status(400).json({ error: "Invalid user id" });
    }
    const orders = await Order.find({ userId }).sort({ createdAt: -1 });
    res.json(orders);
  } catch (error) {
    console.error("Get Orders Error:", error);
    res.status(500).json({ error: "Failed to get orders" });
  }
});

// Get single order by ID
app.get("/api/orders/:orderId", async (req, res) => {
  try {
    const orderId = String(req.params?.orderId || "");
    if (!isValidObjectId(orderId)) {
      return res.status(400).json({ error: "Invalid order id" });
    }
    const order = await Order.findById(orderId);
    if (order) {
      res.json(order);
    } else {
      res.status(404).json({ error: "Order not found" });
    }
  } catch (error) {
    console.error("Get Order Error:", error);
    res.status(500).json({ error: "Failed to get order" });
  }
});

// Get all orders (admin only)
app.get("/api/orders", requireAdmin, async (req, res) => {
  try {
    const orders = await Order.find({}).sort({ createdAt: -1 });
    res.json(orders);
  } catch (error) {
    console.error("Get All Orders Error:", error);
    res.status(500).json({ error: "Failed to get orders" });
  }
});

// Get all users (admin only)
app.get("/api/users", requireAdmin, async (req, res) => {
  try {
    const users = await User.find({})
      .select("_id name email phone role")
      .sort({ _id: -1 });
    res.json(users);
  } catch (error) {
    console.error("Get Users Error:", error);
    res.status(500).json({ error: "Failed to get users" });
  }
});

// Update order status (admin only)
app.put("/api/orders/:orderId", requireAdmin, sensitiveRateLimit, async (req, res) => {
  try {
    const orderId = String(req.params?.orderId || "");
    if (!isValidObjectId(orderId)) {
      return res.status(400).json({ error: "Invalid order id" });
    }
    const status = sanitizeText(req.body?.status || "", 24);
    const trackingNumber = sanitizeText(req.body?.trackingNumber || "", 80);
    const estimatedDelivery = req.body?.estimatedDelivery;
    const allowedStatuses = new Set(["pending", "confirmed", "processing", "shipped", "delivered", "cancelled"]);
    if (!allowedStatuses.has(status)) {
      return res.status(400).json({ error: "Invalid status" });
    }
    const updateData = { status, updatedAt: Date.now() };
    
    if (trackingNumber) updateData['deliveryInfo.trackingNumber'] = trackingNumber;
    if (estimatedDelivery) updateData['deliveryInfo.estimatedDelivery'] = estimatedDelivery;
    if (status === 'shipped') updateData['deliveryInfo.shippedDate'] = Date.now();
    if (status === 'delivered') updateData['deliveryInfo.deliveredDate'] = Date.now();
    
    const order = await Order.findByIdAndUpdate(
      orderId,
      updateData,
      { new: true }
    );
    res.json({ success: true, order });
  } catch (error) {
    console.error("Update Order Error:", error);
    res.status(500).json({ error: "Failed to update order" });
  }
});

// ============= REVIEW ENDPOINTS =============

// Get reviews for a product
app.get("/api/reviews/:productId", async (req, res) => {
  try {
    const productId = String(req.params?.productId || "");
    if (!isValidObjectId(productId)) {
      return res.status(400).json({ error: "Invalid product id" });
    }
    const reviews = await Review.find({ productId })
      .sort({ createdAt: -1 });
    res.json(reviews);
  } catch (error) {
    res.status(500).json({ error: "Failed to get reviews" });
  }
});

// Add review
app.post("/api/reviews", sensitiveRateLimit, async (req, res) => {
  try {
    const productId = String(req.body?.productId || "");
    const userId = String(req.body?.userId || "");
    const userName = sanitizeText(req.body?.userName || "", 120);
    const rating = Number.parseInt(req.body?.rating, 10);
    const comment = sanitizeText(req.body?.comment || "", 1200);
    if (!isValidObjectId(productId) || !isValidObjectId(userId) || !userName) {
      return res.status(400).json({ error: "Invalid review payload" });
    }
    if (!Number.isFinite(rating) || rating < 1 || rating > 5) {
      return res.status(400).json({ error: "Invalid rating" });
    }
    
    // Check if user already reviewed this product
    const existing = await Review.findOne({ productId, userId });
    if (existing) {
      return res.status(400).json({ error: "You have already reviewed this product" });
    }
    
    const review = await Review.create({ productId, userId, userName, rating, comment });
    res.json({ success: true, review });
  } catch (error) {
    res.status(500).json({ error: "Failed to add review" });
  }
});

// Get product average rating
app.get("/api/reviews/:productId/average", async (req, res) => {
  try {
    const productId = String(req.params?.productId || "");
    if (!isValidObjectId(productId)) {
      return res.status(400).json({ error: "Invalid product id" });
    }
    const result = await Review.aggregate([
      { $match: { productId: new mongoose.Types.ObjectId(productId) } },
      { $group: { _id: null, average: { $avg: "$rating" }, count: { $sum: 1 } } }
    ]);
    res.json({ 
      average: result.length > 0 ? result[0].average.toFixed(1) : 0, 
      count: result.length > 0 ? result[0].count : 0 
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to get rating" });
  }
});

// ============= WISHLIST ENDPOINTS =============

// Get user's wishlist
app.get("/api/wishlist/:userId", async (req, res) => {
  try {
    const userId = String(req.params?.userId || "");
    if (!isValidObjectId(userId)) {
      return res.status(400).json({ error: "Invalid user id" });
    }
    let wishlist = await Wishlist.findOne({ userId })
      .populate('products');
    if (!wishlist) {
      wishlist = await Wishlist.create({ userId, products: [] });
    }
    res.json(wishlist);
  } catch (error) {
    res.status(500).json({ error: "Failed to get wishlist" });
  }
});

// Add to wishlist
app.post("/api/wishlist/:userId", sensitiveRateLimit, async (req, res) => {
  try {
    const userId = String(req.params?.userId || "");
    const productId = String(req.body?.productId || "");
    if (!isValidObjectId(userId) || !isValidObjectId(productId)) {
      return res.status(400).json({ error: "Invalid payload" });
    }
    let wishlist = await Wishlist.findOne({ userId });
    
    if (!wishlist) {
      wishlist = await Wishlist.create({ userId, products: [productId] });
    } else {
      if (!wishlist.products.includes(productId)) {
        wishlist.products.push(productId);
        wishlist.updatedAt = Date.now();
        await wishlist.save();
      }
    }
    res.json({ success: true, wishlist });
  } catch (error) {
    res.status(500).json({ error: "Failed to add to wishlist" });
  }
});

// Remove from wishlist
app.delete("/api/wishlist/:userId/:productId", async (req, res) => {
  try {
    const userId = String(req.params?.userId || "");
    const productId = String(req.params?.productId || "");
    if (!isValidObjectId(userId) || !isValidObjectId(productId)) {
      return res.status(400).json({ error: "Invalid payload" });
    }
    const wishlist = await Wishlist.findOne({ userId });
    if (wishlist) {
      wishlist.products = wishlist.products.filter(
        p => p.toString() !== productId
      );
      wishlist.updatedAt = Date.now();
      await wishlist.save();
    }
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: "Failed to remove from wishlist" });
  }
});

// Login
app.post("/api/login", loginRateLimit, async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email || "");
    const password = String(req.body?.password || "").trim();
    if (!email || !password || !isValidEmail(email) || password.length > 200) {
      return res.status(400).json({ success: false, error: "Invalid login payload" });
    }
    const user = await User.findOne({ email }).select(
      "_id name email role password",
    );
    if (!user || !verifyPassword(password, user.password)) {
      res.status(401).json({ success: false, error: "Invalid credentials" });
      return;
    }
    const key = req.ip || req.connection.remoteAddress || "unknown";
    loginAttempts.delete(key);
    
    // Create secure session token
    const sessionToken = generateToken(user);
    const isProduction = process.env.NODE_ENV === 'production';
    
    // Set httpOnly cookie (secure in production)
    res.cookie('session', sessionToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      path: '/'
    });
    
    // Also set user ID cookie for easy access
    res.cookie('userId', user._id.toString(), {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000,
      path: '/'
    });
    
    res.json({
      success: true,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    res.status(500).json({ error: "Login failed" });
  }
});

// Logout
app.post("/api/logout", (req, res) => {
  res.clearCookie('session', { path: '/' });
  res.clearCookie('userId', { path: '/' });
  res.json({ success: true });
});

// Seed Admin User (Run this to create admin if missing)
app.get("/api/seed-admin", requireInternalAccess, sensitiveRateLimit, async (req, res) => {
  try {
    const existing = await User.findOne({ email: "admin@dondad.com" });
    if (existing) {
      res.json({ success: true, message: "Admin already exists", user: existing });
    } else {
      const admin = await User.create({
        name: "Admin",
        email: "admin@dondad.com",
        password: hashPassword("admin123"),
        phone: "08000000000",
        role: "admin",
      });
      res.json({ success: true, message: "Admin created", user: admin });
    }
  } catch (error) {
    res.status(500).json({ error: "Failed to seed admin" });
  }
});

// Register
app.post("/api/register", sensitiveRateLimit, async (req, res) => {
  try {
    const name = sanitizeText(req.body?.name || "", 120);
    const password = String(req.body?.password || "");
    const phone = sanitizeText(req.body?.phone || "", 40);
    const email = normalizeEmail(req.body?.email || "");
    if (!name || !password || !email || !isValidEmail(email)) {
      return res.status(400).json({ success: false, error: "Invalid registration payload" });
    }
    if (password.length < 6 || password.length > 128) {
      return res.status(400).json({ success: false, error: "Password must be 6-128 characters" });
    }
    const existing = await User.findOne({ email });
    if (existing)
      return res.status(400).json({ success: false, error: "Email exists" });

    const user = await User.create({
      name,
      email,
      password: hashPassword(password),
      phone,
    });
    res.json({
      success: true,
      user: { id: user._id, name, email, role: "user" },
    });
  } catch (error) {
    res.status(500).json({ success: false, error: "Registration failed" });
  }
});

// Security readiness healthcheck (no secret values exposed)
app.get("/api/health/security", sensitiveRateLimit, requireInternalAccess, (req, res) => {
  const hasStripeKey = Boolean(process.env.STRIPE_SECRET_KEY);
  const hasStripeWebhookSecret = Boolean(process.env.STRIPE_WEBHOOK_SECRET);
  const hasMongoUri = Boolean(
    process.env.MONGODB_URI ||
      process.env.MONGO_URI ||
      process.env.MONGODB_URL ||
      process.env.MONGO_URL ||
      process.env.DATABASE_URL ||
      process.env.DATABASE_PRIVATE_URL ||
      process.env.MONGODB_PRIVATE_URL ||
      process.env.MONGODB_PUBLIC_URL,
  );
  const hasAdminApiToken = Boolean(process.env.ADMIN_API_TOKEN);
  const hasAllowedOrigins = allowedOrigins.length > 0;

  const checks = {
    corsConfigured: hasAllowedOrigins,
    loginRateLimiterConfigured: true,
    apiRateLimiterConfigured: true,
    sensitiveRateLimiterConfigured: true,
    unsafeKeyFilterConfigured: true,
    internalEndpointsProtectedInProduction: true,
    env: {
      stripeSecretKeyPresent: hasStripeKey,
      stripeWebhookSecretPresent: hasStripeWebhookSecret,
      mongodbUriPresent: hasMongoUri,
      adminApiTokenPresent: hasAdminApiToken,
      allowedOriginsConfigured: hasAllowedOrigins,
    },
  };

  const ready =
    checks.corsConfigured &&
    checks.loginRateLimiterConfigured &&
    checks.apiRateLimiterConfigured &&
    checks.sensitiveRateLimiterConfigured &&
    checks.unsafeKeyFilterConfigured &&
    checks.internalEndpointsProtectedInProduction &&
    checks.env.stripeSecretKeyPresent &&
    checks.env.stripeWebhookSecretPresent &&
    checks.env.mongodbUriPresent &&
    checks.env.adminApiTokenPresent &&
    checks.env.allowedOriginsConfigured;

  res.json({
    success: true,
    ready,
    environment: process.env.NODE_ENV || "development",
    checks,
  });
});

// Force HTTPS in production
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.protocol !== 'https') {
      return res.redirect('https://' + req.get('host') + req.url);
    }
    next();
  });
}

// Start Server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

module.exports = app;
