const { Pool } = require('pg');

let pool;

function getPool() {
  if (!pool) {
    if (!process.env.DATABASE_URL) {
      throw new Error(
        'DATABASE_URL is missing. Add your Neon PostgreSQL connection string to .env.'
      );
    }

    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl:
        process.env.NODE_ENV === 'production' ||
        process.env.DATABASE_URL.includes('neon.tech')
          ? { rejectUnauthorized: false }
          : undefined,
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000
    });
  }

  return pool;
}

async function query(text, params = []) {
  console.log('\n[DB QUERY]');
  console.log(text);
  console.log('[DB PARAMS]', params.map((value, index) => {
    if (index === 0 && typeof value === 'string' && value.includes(':')) {
      return '[REDACTED]';
    }
    return value;
  }));

  return await getPool().query(text, params);
}

async function connectDB() {
  const result = await query('SELECT NOW() AS now');
  console.log(`[DB] Connected to PostgreSQL (${result.rows[0].now})`);
  return true;
}

async function closeDB() {
  if (pool) {
    await pool.end();
    pool = null;
  }
}

module.exports = {
  getPool,
  query,
  connectDB,
  closeDB
};