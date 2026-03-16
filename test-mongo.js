const { MongoClient, ServerApiVersion } = require('mongodb');
const uri = process.env.MONGODB_URI || "mongodb+srv://ugwunekejohn5_db_user:<db_password>@cluster0.r5kxjyu.mongodb.net/?appName=Cluster0";
console.log('Testing URI:', uri.replace(/\/\/[^@]+@/, '//***:***@'));

const client = new MongoClient(uri);

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
