import "dotenv/config";
import { MongoClient } from "mongodb";

const email = process.argv[2];
if (!email) {
  console.error("Usage: node make-admin.js <email>");
  process.exit(1);
}

const client = new MongoClient(process.env.MONGODB_URI);

try {
  await client.connect();
  const db = client.db(process.env.DB_NAME || "wedplan");
  const result = await db
    .collection("user")
    .updateOne({ email }, { $set: { role: "admin", isBlocked: false } });

  console.log(
    result.matchedCount
      ? `${email} is now an admin.`
      : "No user found with that email. Sign up first.",
  );
} finally {
  await client.close();
}
