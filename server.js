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

const app = express();
const PORT = process.env.PORT || 3000;

const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 10;
const loginAttempts = new Map();

// MongoDB Connection
const MONGODB_URI =
  "mongodb+srv://ugwunekejohn5_db_user:Legend1@cluster0.r5kxjyu.mongodb.net/pajaygadgets?retryWrites=true&w=majority&appName=Cluster0";

mongoose
  .connect(MONGODB_URI)
  .then(async () => {
    console.log("Connected to MongoDB");
    await seedDatabase(); // Run seed after connection
    await ensureDefaultUsers();
    await migrateLegacyPasswords();
  })
  .catch((err) => console.error("MongoDB connection error:", err));

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
    notes: { type: String }
  },
  paymentMethod: { type: String },
  subtotal: { type: Number },
  status: { type: String, default: "pending" }, // pending, confirmed, shipped, delivered, cancelled
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);
const Product = mongoose.model("Product", productSchema);
const Cart = mongoose.model("Cart", cartSchema);
const Order = mongoose.model("Order", orderSchema);

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
  if (!isPasswordHashed(storedPassword)) {
    return inputPassword === storedPassword;
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
  const users = await User.find({});
  for (const user of users) {
    if (!isPasswordHashed(user.password)) {
      user.password = hashPassword(user.password);
      await user.save();
      console.log(`Migrated password hash for: ${user.email}`);
    }
  }
}

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
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname));

// --- API ROUTES ---

// Get all products
app.get("/api/products", async (req, res) => {
  try {
    const { category, search } = req.query;
    let query = {};
    if (category && category !== "all") query.category = category;
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: "i" } },
        { desc: { $regex: search, $options: "i" } },
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
    const product = await Product.findById(req.params.id);
    if (product) {
      res.json(product);
    } else {
      res.status(404).json({ error: "Product not found" });
    }
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch product" });
  }
});

// Update product
app.put("/api/products/:id", async (req, res) => {
  try {
    const product = await Product.findByIdAndUpdate(
      req.params.id,
      req.body,
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

// Delete product
app.delete("/api/products/:id", async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
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
app.get("/api/products/migrate-variants", async (req, res) => {
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
    if (!userId || userId === "undefined" || userId.length < 12) {
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
    const { qty, selectedVariant, unitPrice } = req.body;
    
    if (!userId || !productId) {
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
    if (selectedVariant) {
      existingQuery["selectedVariant.storage"] = selectedVariant.storage || "";
      existingQuery["selectedVariant.ram"] = selectedVariant.ram || "";
      existingQuery["selectedVariant.color"] = selectedVariant.color || "";
    }
    
    const existing = await Cart.findOne(existingQuery);
    if (existing) {
      existing.qty += qty || 1;
      await existing.save();
    } else {
      await Cart.create({
        userId,
        productId,
        qty: qty || 1,
        selectedVariant: selectedVariant || { storage: "", ram: "", color: "" },
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
    const { qty, selectedVariant } = req.body;
    
    const query = { userId, productId };
    if (selectedVariant) {
      query["selectedVariant.storage"] = selectedVariant.storage || "";
      query["selectedVariant.ram"] = selectedVariant.ram || "";
      query["selectedVariant.color"] = selectedVariant.color || "";
    }
    
    if (qty !== undefined && qty <= 0) {
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
    
    const query = { userId, productId };
    if (selectedVariant) {
      try {
        const variant = JSON.parse(selectedVariant);
        query["selectedVariant.storage"] = variant.storage || "";
        query["selectedVariant.ram"] = variant.ram || "";
        query["selectedVariant.color"] = variant.color || "";
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
app.post("/api/orders", async (req, res) => {
  try {
    const { userId, userName, userEmail, userPhone, items, deliveryInfo, paymentMethod, subtotal } = req.body;
    
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
    
    // Clear user's cart after order
    await Cart.deleteMany({ userId });
    
    res.json({ success: true, order });
  } catch (error) {
    console.error("Create Order Error:", error);
    res.status(500).json({ error: "Failed to create order" });
  }
});

// Get user's orders
app.get("/api/orders/user/:userId", async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.params.userId }).sort({ createdAt: -1 });
    res.json(orders);
  } catch (error) {
    console.error("Get Orders Error:", error);
    res.status(500).json({ error: "Failed to get orders" });
  }
});

// Get all orders (for admin)
app.get("/api/orders", async (req, res) => {
  try {
    const orders = await Order.find({}).sort({ createdAt: -1 });
    res.json(orders);
  } catch (error) {
    console.error("Get All Orders Error:", error);
    res.status(500).json({ error: "Failed to get orders" });
  }
});

// Update order status (for admin)
app.put("/api/orders/:orderId", async (req, res) => {
  try {
    const { status } = req.body;
    const order = await Order.findByIdAndUpdate(
      req.params.orderId,
      { status },
      { new: true }
    );
    res.json({ success: true, order });
  } catch (error) {
    console.error("Update Order Error:", error);
    res.status(500).json({ error: "Failed to update order" });
  }
});

// Login
app.post("/api/login", loginRateLimit, async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email || "");
    const password = (req.body?.password || "").trim();
    const user = await User.findOne({ email }).select(
      "_id name email role password",
    );
    if (!user || !verifyPassword(password, user.password)) {
      res.status(401).json({ success: false, error: "Invalid credentials" });
      return;
    }
    const key = req.ip || req.connection.remoteAddress || "unknown";
    loginAttempts.delete(key);
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

// Seed Admin User (Run this to create admin if missing)
app.get("/api/seed-admin", async (req, res) => {
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
app.post("/api/register", async (req, res) => {
  try {
    const { name, password, phone } = req.body;
    const email = normalizeEmail(req.body?.email || "");
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

// Start Server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

module.exports = app;
