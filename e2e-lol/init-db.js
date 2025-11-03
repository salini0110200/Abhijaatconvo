
require('dotenv').config();
const { Pool } = require('pg');

const { DATABASE_URL } = process.env;

if (!DATABASE_URL) {
  console.error('ERROR: DATABASE_URL not set');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL ? { rejectUnauthorized: false } : false,
});

async function initDatabase() {
  try {
    console.log('Creating users table...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        public_key TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT now()
      )
    `);

    console.log('Creating messages table...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        recipient_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        ciphertext TEXT NOT NULL,
        nonce TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT now(),
        delivered BOOLEAN DEFAULT FALSE
      )
    `);

    console.log('✓ Database tables created successfully!');
    await pool.end();
    process.exit(0);
  } catch (err) {
    console.error('Error initializing database:', err);
    await pool.end();
    process.exit(1);
  }
}

initDatabase();
