const dns = require('node:dns');
// Use Google DNS servers
dns.setServers(["8.8.8.8", "1.1.1.1"]);
console.log('DNS servers set to:', dns.getServers());

require('dotenv').config();
const { MongoClient, ServerApiVersion } = require('mongodb');
const uri = process.env.MONGODB_URI;
if (!uri) {
  console.error('MONGODB_URI is not defined in .env file');
  process.exit(1);
}
console.log('Testing URI:', uri.replace(/\/\/[^@]+@/, '//***:***@'));

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    await client.connect();
    await client.db("admin").command({ ping: 1 });
    console.log("✅ MongoDB Connection SUCCESSFUL!");
    console.log("Your URI works correctly.");
  } catch (error) {
    console.error("❌ MongoDB Connection FAILED:");
    console.error(error);
  } finally {
    await client.close();
  }
}

run().catch(console.dir);