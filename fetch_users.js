const mongoose = require('mongoose');
const fs = require('fs');
require('dotenv').config();

const MONGODB_URI = process.env.MONGODB_URI;

mongoose.connect(MONGODB_URI, {
  serverSelectionTimeoutMS: 5000
}).then(async () => {
  console.log("Connected to MongoDB");
  const db = mongoose.connection.db;
  const users = await db.collection('users').find({}).toArray();
  const logins = users.map(u => ({ email: u.email, passwordHash: u.password, name: u.name, role: u.role }));
  
  fs.writeFileSync('users_dump.json', JSON.stringify(logins, null, 2));
  console.log(`Saved ${logins.length} users to users_dump.json`);
  
  // Also print directly
  console.log("\n--- Users ---");
  logins.forEach(l => console.log(`Email: ${l.email} | Role: ${l.role} | Password Hash: ${l.passwordHash.substring(0, 15)}...`));
  
  process.exit(0);
}).catch(err => {
  console.error("Connection error:", err);
  process.exit(1);
});
