require('dotenv').config();
const { MongoClient, ServerApiVersion } = require('mongodb');

// We'll try to connect using one of the hosts from the SRV record and the standard port
const uri = 'mongodb://ugwunekejohn5_db_user:rAqSq5SSSlcsLdnH@ac-05qfvvj-shard-00-00.r5kxjyu.mongodb.net:27017/dondadtech?retryWrites=true&w=majority';
console.log('Testing URI with IP host:', uri.replace(/\/\/[^@]+@/, '//***:***@'));

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
    console.error(error.message);
  } finally {
    await client.close();
  }
}

run().catch(console.dir);