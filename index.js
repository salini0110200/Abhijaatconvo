require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const helmet = require('helmet');

const app = express();
app.use(helmet());
app.use(cors());
app.use(bodyParser.json({ limit: '1mb' }));
app.use(express.static('public'));

// Environment variables (set on Render)
const {
  DATABASE_URL,
  JWT_SECRET = 'change-this-secret',
  PORT = 3000
} = process.env;

if (!DATABASE_URL) {
  console.warn('WARNING: DATABASE_URL not set. Local dev only.');
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL ? { rejectUnauthorized: false } : false,
});

// Helper: simple auth middleware using JWT
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Missing Authorization header' });
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Bad Authorization' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // { id, username }
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

/*
Database schema (run once):
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  public_key TEXT NOT NULL, -- base64 or hex or raw depending on client lib
  created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE messages (
  id SERIAL PRIMARY KEY,
  sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  recipient_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  ciphertext TEXT NOT NULL,
  nonce TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT now(),
  delivered BOOLEAN DEFAULT FALSE
);
*/

// Utility: get user by username
async function getUserByUsername(username) {
  const { rows } = await pool.query('SELECT id, username, public_key FROM users WHERE username=$1', [username]);
  return rows[0];
}

// 1) Register - creates user with username, password, publicKey
app.post('/register', async (req, res) => {
  try {
    const { username, password, publicKey } = req.body;
    if (!username || !password || !publicKey) return res.status(400).json({ error: 'username, password, publicKey required' });
    const passwordHash = await bcrypt.hash(password, 10);
    const q = 'INSERT INTO users (username, password_hash, public_key) VALUES ($1, $2, $3) RETURNING id, username';
    const { rows } = await pool.query(q, [username, passwordHash, publicKey]);
    const user = rows[0];
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ ok: true, token });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'username taken' });
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// 2) Login - returns JWT
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username & password required' });
    const { rows } = await pool.query('SELECT id, username, password_hash FROM users WHERE username=$1', [username]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'invalid credentials' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ ok: true, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// 3) Publish/Update public key (optional)
app.post('/me/public-key', authMiddleware, async (req, res) => {
  try {
    const { publicKey } = req.body;
    if (!publicKey) return res.status(400).json({ error: 'publicKey required' });
    await pool.query('UPDATE users SET public_key=$1 WHERE id=$2', [publicKey, req.user.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// 4) Lookup public key for a username (used by client to encrypt)
app.get('/keys/:username', async (req, res) => {
  try {
    const user = await getUserByUsername(req.params.username);
    if (!user) return res.status(404).json({ error: 'user_not_found' });
    res.json({ username: user.username, publicKey: user.public_key });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// 5) Send message - client provides recipient username and ciphertext+nonce (server stores)
app.post('/send', authMiddleware, async (req, res) => {
  try {
    const { to, ciphertext, nonce } = req.body;
    if (!to || !ciphertext || !nonce) return res.status(400).json({ error: 'to, ciphertext, nonce required' });

    const recipient = await getUserByUsername(to);
    if (!recipient) return res.status(404).json({ error: 'recipient_not_found' });

    // store
    await pool.query(
      'INSERT INTO messages (sender_id, recipient_id, ciphertext, nonce) VALUES ($1, $2, $3, $4)',
      [req.user.id, recipient.id, ciphertext, nonce]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// 6) Retrieve messages for logged-in user (returns ciphertext & nonce). Mark as delivered optional.
app.get('/messages', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT m.id, u.username as from, m.ciphertext, m.nonce, m.created_at
       FROM messages m JOIN users u ON m.sender_id = u.id
       WHERE m.recipient_id = $1
       ORDER BY m.created_at ASC
       LIMIT 100`,
      [req.user.id]
    );
    // Optionally mark delivered:
    const ids = rows.map(r => r.id);
    if (ids.length) {
      await pool.query('UPDATE messages SET delivered = TRUE WHERE id = ANY($1::int[])', [ids]);
    }
    res.json({ messages: rows.map(r => ({ id: r.id, from: r.from, ciphertext: r.ciphertext, nonce: r.nonce, ts: r.created_at })) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// 7) Simple health
app.get('/health', (req,res) => res.json({ ok:true }));

const port = process.env.PORT || PORT;
app.listen(port, () => {
  console.log(`E2EE inbox server listening on ${port}`);
});
