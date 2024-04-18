const { MongoClient, ServerApiVersion } = require('mongodb');

// DONT CHANGE const uri IF U DONT KNOW WHAT IT MEANS

const uri = "mongodb+srv://mongodblvp:2KCTKoT5WQNbKBus@geojot.mx56hed.mongodb.net/?retryWrites=true&w=majority&appName=GeoJot";
//  const uri = "mongodb+srv://rafaelmcruzz:vlDT9RvXDSiCFMq5@geojotmongodb.mjygfhl.mongodb.net/?retryWrites=true&w=majority&appName=GeoJotMongoDB";
//const uri = "mongodb+srv://javanpang26:GZKNyeBxCGhNGZRq@geojot.qyntlul.mongodb.net/?retryWrites=true&w=majority";

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function connectToDatabase() {
  try {
    await client.connect();
    console.log("Connected to MongoDB database");
    return client;
  } catch (error) {
    console.error("Error connecting to MongoDB:", error);
    throw error;
  }
}

module.exports = connectToDatabase;