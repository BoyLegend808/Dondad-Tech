const dns = require('node:dns');
if (!process.env.RENDER) {
    dns.setServers(['8.8.8.8', '1.1.1.1']);
}

const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const path = require("path");
const mongoose = require("mongoose");

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB Connection
const MONGODB_URI =
  "mongodb+srv://ugwunekejohn5_db_user:Legend1@cluster0.r5kxjyu.mongodb.net/dondadtech?retryWrites=true&w=majority&appName=Cluster0";

mongoose
  .connect(MONGODB_URI)
  .then(() => {
    console.log("Connected to MongoDB");
    seedDatabase(); // Run seed after connection
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
  desc: { type: String, default: "" },
});

const cartSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  productId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Product",
    required: true,
  },
  qty: { type: Number, default: 1 },
});

const User = mongoose.model("User", userSchema);
const Product = mongoose.model("Product", productSchema);
const Cart = mongoose.model("Cart", cartSchema);

// Seed initial data
async function seedDatabase() {
  try {
    const userCount = await User.countDocuments();
    if (userCount === 0) {
      await User.create({
        name: "Admin",
        email: "admin@dondad.com",
        password: "admin123",
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

// Cart Route with SAFETY CHECK (Fixes the "undefined" error)
app.get("/api/cart", async (req, res) => {
  try {
    const userId = req.query.userId;
    // This check prevents Mongoose from trying to search for an "undefined" ID
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

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email, password }).select(
      "_id name email role",
    );
    if (user) {
      res.json({ success: true, user });
    } else {
      res.status(401).json({ success: false, error: "Invalid credentials" });
    }
  } catch (error) {
    res.status(500).json({ error: "Login failed" });
  }
});

// Register
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    const existing = await User.findOne({ email });
    if (existing)
      return res.status(400).json({ success: false, error: "Email exists" });

    const user = await User.create({ name, email, password, phone });
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
