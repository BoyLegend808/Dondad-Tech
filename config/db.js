const mongoose = require('mongoose');

let dbReady = false;
let mongooseConnection = null;

async function connectDB() {
  if (dbReady && mongooseConnection) {
    console.log('[DB] Already connected to MongoDB');
    return { ready: true, connection: mongooseConnection };
  }

  const MONGODB_URI = resolveMongoUri();
  
  if (!MONGODB_URI) {
    console.error(
      '[DB] Missing MongoDB URI. Set one of: MONGODB_URI, MONGO_URI, MONGODB_URL, MONGO_URL, DATABASE_URL, DATABASE_PRIVATE_URL, MONGODB_PRIVATE_URL, MONGODB_PUBLIC_URL'
    );
    return { ready: false, error: 'Missing DB URI' };
  }

  try {
    mongooseConnection = await mongoose.connect(MONGODB_URI, {
      maxPoolSize: 50,
      minPoolSize: 5,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      maxIdleTimeMS: 30000,
    });

    mongoose.set('strictQuery', false);
    dbReady = true;
    console.log('[DB] ✅ Connected to MongoDB');
    return { ready: true, connection: mongooseConnection };
  } catch (error) {
    console.error('[DB] ❌ Connection failed:', error.message);
    dbReady = false;
    return { ready: false, error: error.message };
  }
}

function resolveMongoUri() {
  const candidates = [
    'MONGODB_URI', 'MONGO_URI', 'MONGODB_URL', 'MONGO_URL',
    'DATABASE_URL', 'DATABASE_PRIVATE_URL', 'MONGODB_PRIVATE_URL', 'MONGODB_PUBLIC_URL'
  ];

  for (const key of candidates) {
    const raw = process.env[key];
    if (!raw) continue;
    
    const cleaned = String(raw).trim().replace(/^['"]|['"]$/g, '');
    if (cleaned) return cleaned;
  }
  return '';
}

function getDBStatus() {
  return {
    ready: dbReady,
    uriSet: Boolean(resolveMongoUri()),
    connection: mongooseConnection ? 'connected' : 'disconnected'
  };
}

module.exports = {
  connectDB,
  getDBStatus,
  mongoose
};

