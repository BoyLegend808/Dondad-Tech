require("dotenv").config();
const mongoose = require("mongoose");

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
    const cleaned = String(raw)
      .trim()
      .replace(/^['"]|['"]$/g, "");
    if (cleaned) return cleaned;
  }
  return "";
}

const MONGODB_URI = resolveMongoUri();
console.log("MONGODB_URI from env:", MONGODB_URI ? "FOUND" : "NOT FOUND");
if (MONGODB_URI) {
  console.log("URI (first 50 chars):", MONGODB_URI.substring(0, 50) + "...");
} else {
  console.error("No MongoDB URI found in environment variables");
  process.exit(1);
}

mongoose.set('strictQuery', false);

mongoose
  .connect(MONGODB_URI, {
    maxPoolSize: 50,
    minPoolSize: 5,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
    maxIdleTimeMS: 30000,
  })
  .then(async () => {
    console.log("✅ Connected to MongoDB with increased pool size (50)");
    await mongoose.disconnect();
    console.log("Disconnected from MongoDB");
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
  });