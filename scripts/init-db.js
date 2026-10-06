require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { query, connectDB, closeDB } = require('../models/db');

async function main() {
  await connectDB();
  const schema = fs.readFileSync(path.join(__dirname, '..', 'schema.sql'), 'utf8');
  await query(schema);
  console.log('[DB] Tables created/verified successfully.');
  await closeDB();
}

main().catch(async err => {
  console.error('[DB] Initialization failed:', err.message);
  await closeDB().catch(() => {});
  process.exit(1);
});
