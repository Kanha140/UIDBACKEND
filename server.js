import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { loadDB, saveDB, initDB, generateApiKey } from './db.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'https://uidbbypass.netlify.app';
const JWT_SECRET = process.env.JWT_SECRET || 'UID_BYPASS_SUPER_SECRET_KEY_2026';

const GTC_API_URL = process.env.API_URL || 'https://gtccheats.xyz/Api/uidbypassapi/api_user.php';
const GTC_API_KEY = process.env.API_KEY || 'GTCAPI-0E9C83D81E2942CACE91A4AF6C86313E';
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || 'https://discordapp.com/api/webhooks/1528755963035783218/9O-3-6EqqzolpuGZnDQRS4tDpRvlKvCXpcVFh8WM3eWu792Lnjh-T7Pwdgh8gBA14WQB';

// Discord Rich Webhook Logger Helper
async function sendDiscordWebhook(title, description, color = 0x7C3AED, fields = []) {
  if (!DISCORD_WEBHOOK_URL) return;
  try {
    const embed = {
      title: title,
      description: description,
      color: color,
      fields: fields,
      footer: { text: "UID Bypass Registry V4.0 — Audit System" },
      timestamp: new Date().toISOString()
    };
    await fetch(DISCORD_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ embeds: [embed] })
    });
  } catch (err) {
    console.error('[Discord Webhook Error]', err.message);
  }
}

// Allowed Origins — ONLY your official Netlify domain & localhost
const ALLOWED_ORIGINS = [
  'https://uidbbypass.netlify.app',
  'http://localhost:5000',
  'http://127.0.0.1:5000',
  'http://localhost:3000',
  'http://127.0.0.1:5500'
];

// 1. CORS Configuration (Supports web clients and local development)
app.use(cors({
  origin: true, // Allow all incoming web origins dynamically
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-KEY', 'X-Client-Signature'],
  credentials: true
}));

app.use(express.json());

// 3. Simple Rate Limiter Protection (Max 40 requests per minute per IP)
const rateLimitMap = new Map();
app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const windowMs = 60 * 1000;
  const maxReqs = 40;

  if (!rateLimitMap.has(ip)) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + windowMs });
  } else {
    const record = rateLimitMap.get(ip);
    if (now > record.resetTime) {
      record.count = 1;
      record.resetTime = now + windowMs;
    } else {
      record.count++;
      if (record.count > maxReqs) {
        return res.status(429).json({
          success: false,
          message: '⚠️ Too many requests! Rate limit exceeded. Please wait a minute.'
        });
      }
    }
  }
  next();
});

// Initialize Database
await initDB();

// Helper: Call External GTC API
async function callGtcApi(action, queryParams = {}, bodyData = null) {
  try {
    const url = new URL(GTC_API_URL);
    url.searchParams.append('action', action);
    for (const [k, v] of Object.entries(queryParams)) {
      url.searchParams.append(k, v);
    }

    const options = {
      method: bodyData ? 'POST' : 'GET',
      headers: {
        'X-API-KEY': GTC_API_KEY,
        'Content-Type': 'application/json'
      },
      signal: AbortSignal.timeout(10000) // 10-second timeout to prevent server hangs
    };
    if (bodyData) {
      options.body = JSON.stringify(bodyData);
    }

    const response = await fetch(url.toString(), options);
    const responseText = await response.text();

    if (!responseText.trim()) {
      return { data: null, error: `Empty response from GTC API (HTTP ${response.status})` };
    }

    try {
      const json = JSON.parse(responseText);
      return { data: json, error: null };
    } catch (e) {
      return { data: null, error: `GTC API returned non-JSON response (HTTP ${response.status})` };
    }
  } catch (err) {
    return { data: null, error: `GTC API network error: ${err.message}` };
  }
}

// Authentication Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// API Key Authentication Middleware for Third-Party API Requests
function authenticateApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'] || req.query.api_key || (req.body && req.body.api_key);
  if (!apiKey) {
    return res.status(401).json({ success: false, message: 'API Key required. Provide header X-API-KEY or api_key parameter.' });
  }

  const db = loadDB();
  const user = db.users.find(u => u.api_key === apiKey);
  if (!user) {
    return res.status(403).json({ success: false, message: 'Invalid or revoked API Key.' });
  }

  req.user = user;
  next();
}

// Helper: Calculate expiry date string
function getExpiryDate(days) {
  const d = new Date();
  d.setDate(d.getDate() + parseInt(days));
  return d.toISOString().split('T')[0] + ' ' + d.toTimeString().split(' ')[0];
}

// ----------------------------------------------------
// PUBLIC ENDPOINTS
// ----------------------------------------------------

// Server Health Check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ONLINE', message: 'UID Bypass Whitelist API Running', timestamp: new Date() });
});

// Public UID Status Lookup (Checks local DB & GTC API)
app.get('/api/whitelist/check/:uid', async (req, res) => {
  const { uid } = req.params;
  const db = loadDB();
  let entry = db.whitelists.find(item => item.account_id === uid);

  // Sync with GTC API
  const { data: gtcData } = await callGtcApi('info', { account_id: uid });

  if (gtcData && gtcData.success && gtcData.data) {
    const d = gtcData.data;
    entry = {
      account_id: d.account_id,
      for_days: d.for_days,
      adder_admin: d.adder_admin || 'API_ADMIN',
      added_time: d.added_time || new Date().toISOString(),
      expiry_date: d.expiry_date
    };
  }

  if (!entry) {
    return res.json({
      success: false,
      isWhitelisted: false,
      message: 'UID is NOT Whitelisted.'
    });
  }

  const isExpired = new Date(entry.expiry_date) < new Date();

  return res.json({
    success: true,
    isWhitelisted: !isExpired,
    data: {
      account_id: entry.account_id,
      for_days: entry.for_days,
      adder_admin: entry.adder_admin,
      added_time: entry.added_time,
      expiry_date: entry.expiry_date,
      status: isExpired ? 'EXPIRED' : 'ACTIVE'
    }
  });
});

// Login Endpoint
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username and Password required' });
  }

  const db = loadDB();
  const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());

  if (!user) {
    return res.status(401).json({ success: false, message: 'Invalid credentials' });
  }

  const validPassword = await bcrypt.compare(password, user.password_hash);
  if (!validPassword) {
    return res.status(401).json({ success: false, message: 'Invalid credentials' });
  }

  // Record Client IP Address
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  user.last_login_ip = clientIp;
  user.last_login_time = new Date().toISOString();

  // Append to login history log
  if (!db.login_history) db.login_history = [];
  db.login_history.push({
    username: user.username,
    role: user.role,
    ip: clientIp,
    login_time: new Date().toISOString()
  });
  // Keep only last 500 history entries
  if (db.login_history.length > 500) db.login_history = db.login_history.slice(-500);
  saveDB(db);

  // Send Discord Audit Log
  sendDiscordWebhook(
    '🔑 Staff Login Session',
    `User **${user.username}** (${user.role}) logged in successfully.`,
    0x06B6D4,
    [
      { name: 'User', value: user.username, inline: true },
      { name: 'Role', value: user.role, inline: true },
      { name: 'IP Address', value: `\`${clientIp}\``, inline: true }
    ]
  );

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  return res.json({
    success: true,
    token,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      credits: user.credits,
      last_login_ip: user.last_login_ip
    }
  });
});

// ----------------------------------------------------
// PROTECTED ENDPOINTS
// ----------------------------------------------------

app.get('/api/auth/me', authenticateToken, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.user.id || u.username.toLowerCase() === req.user.username.toLowerCase());
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }
  res.json({
    success: true,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      credits: user.credits,
      last_login_ip: user.last_login_ip
    }
  });
});

// User Management
app.post('/api/users/create', authenticateToken, async (req, res) => {
  const { username, password, role, initialCredits } = req.body;
  const currentUserRole = req.user.role;

  if (!username || !password || !role) {
    return res.status(400).json({ success: false, message: 'Username, password, and role are required.' });
  }

  const targetRole = role.toUpperCase();

  if (currentUserRole === 'ADMIN') {
    if (!['SELLER', 'RESELLER', 'API_SELLER', 'API_USER'].includes(targetRole)) {
      return res.status(400).json({ success: false, message: 'Admin can create SELLER, RESELLER, API_SELLER, or API_USER.' });
    }
  } else if (currentUserRole === 'SELLER') {
    if (!['RESELLER', 'API_SELLER', 'API_USER'].includes(targetRole)) {
      return res.status(403).json({ success: false, message: 'Sellers can create RESELLER, API_SELLER, or API_USER accounts.' });
    }
  } else if (currentUserRole === 'API_SELLER') {
    if (targetRole !== 'API_USER') {
      return res.status(403).json({ success: false, message: 'API Sellers can ONLY create API_USER accounts.' });
    }
  } else {
    return res.status(403).json({ success: false, message: 'Resellers and API Users do not have permission to create users.' });
  }

  const db = loadDB();

  if (db.users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
    return res.status(400).json({ success: false, message: 'Username already exists.' });
  }

  const salt = await bcrypt.genSalt(10);
  const password_hash = await bcrypt.hash(password, salt);

  const newUser = {
    id: 'usr_' + Date.now(),
    username: username.trim(),
    password_hash,
    role: targetRole,
    created_by: req.user.username,
    credits: parseInt(initialCredits) || 0,
    api_key: generateApiKey(),
    created_at: new Date().toISOString(),
    last_login_ip: 'Not logged in yet'
  };

  db.users.push(newUser);
  saveDB(db);

  // Send Discord Audit Log
  sendDiscordWebhook(
    '👤 Staff Account Created',
    `New **${targetRole}** account created by **${req.user.username}**.`,
    0x10B981,
    [
      { name: 'New Staff', value: newUser.username, inline: true },
      { name: 'Role', value: targetRole, inline: true },
      { name: 'Created By', value: req.user.username, inline: true },
      { name: 'Initial Credits', value: `${newUser.credits}`, inline: true }
    ]
  );

  res.json({
    success: true,
    message: `${targetRole} created successfully!`,
    user: {
      id: newUser.id,
      username: newUser.username,
      role: newUser.role,
      credits: newUser.credits,
      created_by: newUser.created_by,
      last_login_ip: newUser.last_login_ip
    }
  });
});

app.get('/api/users', authenticateToken, (req, res) => {
  const db = loadDB();
  let filterUsers = [];

  if (req.user.role === 'ADMIN') {
    filterUsers = db.users.map(u => ({
      id: u.id,
      username: u.username,
      role: u.role,
      credits: u.credits,
      created_by: u.created_by,
      created_at: u.created_at,
      last_login_ip: u.last_login_ip || 'Not logged in yet'
    }));
  } else if (req.user.role === 'SELLER') {
    filterUsers = db.users
      .filter(u => u.created_by === req.user.username || u.role === 'RESELLER' || u.role === 'API_USER' || u.role === 'API_SELLER')
      .map(u => ({
        id: u.id,
        username: u.username,
        role: u.role,
        credits: u.credits,
        created_by: u.created_by,
        created_at: u.created_at,
        last_login_ip: u.last_login_ip || 'Not logged in yet'
      }));
  } else if (req.user.role === 'API_SELLER') {
    filterUsers = db.users
      .filter(u => u.created_by === req.user.username || u.role === 'API_USER')
      .map(u => ({
        id: u.id,
        username: u.username,
        role: u.role,
        credits: u.credits,
        created_by: u.created_by,
        created_at: u.created_at,
        last_login_ip: u.last_login_ip || 'Not logged in yet'
      }));
  } else {
    filterUsers = [];
  }

  res.json({ success: true, users: filterUsers });
});

// Delete User (Admin can delete Seller/Reseller/API_SELLER, Seller/API_SELLER can delete their own users)
app.delete('/api/users/:userId', authenticateToken, (req, res) => {
  const { userId } = req.params;
  const db = loadDB();

  const targetUser = db.users.find(u => u.id === userId);
  if (!targetUser) {
    return res.status(404).json({ success: false, message: 'User not found.' });
  }

  // Cannot delete yourself
  if (targetUser.id === req.user.id) {
    return res.status(400).json({ success: false, message: 'You cannot delete your own account.' });
  }

  // Cannot delete ADMIN accounts
  if (targetUser.role === 'ADMIN') {
    return res.status(403).json({ success: false, message: 'Admin accounts cannot be deleted.' });
  }

  // Seller / API Seller can only delete accounts created by them
  if ((req.user.role === 'SELLER' || req.user.role === 'API_SELLER') && targetUser.created_by !== req.user.username) {
    return res.status(403).json({ success: false, message: 'You can only delete accounts created by your account.' });
  }

  // Resellers cannot delete anyone
  if (req.user.role === 'RESELLER') {
    return res.status(403).json({ success: false, message: 'Resellers do not have permission to delete accounts.' });
  }

  db.users = db.users.filter(u => u.id !== userId);
  saveDB(db);

  // Send Discord Audit Log
  sendDiscordWebhook(
    '🗑️ Staff Account Deleted',
    `Account **${targetUser.username}** (${targetUser.role}) was deleted by **${req.user.username}**.`,
    0xEF4444,
    [
      { name: 'Deleted User', value: targetUser.username, inline: true },
      { name: 'Role', value: targetUser.role, inline: true },
      { name: 'Deleted By', value: req.user.username, inline: true }
    ]
  );

  res.json({ success: true, message: `Account "${targetUser.username}" has been deleted successfully.` });
});

// Login History Logging - record each login event
app.post('/api/auth/login', async (req, res) => {
  // Note: This is handled above in the main login route, login_history is stored per-user
});

app.get('/api/login-history', authenticateToken, (req, res) => {
  const db = loadDB();

  let history = db.login_history || [];

  if (req.user.role === 'ADMIN') {
    // Admin sees all history
  } else if (req.user.role === 'SELLER') {
    // Seller sees only history of users they created
    const myUsernames = db.users
      .filter(u => u.created_by === req.user.username)
      .map(u => u.username);
    history = history.filter(h => myUsernames.includes(h.username));
  } else {
    // Reseller sees only their own history
    history = history.filter(h => h.username === req.user.username);
  }

  // Return latest 100 entries sorted by newest first
  history = history.sort((a, b) => new Date(b.login_time) - new Date(a.login_time)).slice(0, 100);

  res.json({ success: true, history });
});

app.post('/api/users/credits', authenticateToken, (req, res) => {
  const { userId, amount, action } = req.body;

  if (!userId || amount === undefined) {
    return res.status(400).json({ success: false, message: 'userId and amount required' });
  }

  const db = loadDB();
  const targetUser = db.users.find(u => u.id === userId);

  if (!targetUser) {
    return res.status(404).json({ success: false, message: 'Target user not found' });
  }

  if (req.user.role === 'SELLER' && targetUser.created_by !== req.user.username) {
    return res.status(403).json({ success: false, message: 'You can only manage credits for Resellers created by you.' });
  }
  if (req.user.role === 'RESELLER') {
    return res.status(403).json({ success: false, message: 'Resellers cannot modify user credits.' });
  }

  const numAmount = parseInt(amount);

  if (action === 'ADD') {
    targetUser.credits += numAmount;
  } else {
    targetUser.credits = numAmount;
  }

  saveDB(db);

  // Send Discord Audit Log
  sendDiscordWebhook(
    '💳 Staff Credits Updated',
    `Credits for **${targetUser.username}** updated by **${req.user.username}**.`,
    0x06B6D4,
    [
      { name: 'Target User', value: targetUser.username, inline: true },
      { name: 'Action', value: action, inline: true },
      { name: 'Amount', value: `${numAmount}`, inline: true },
      { name: 'New Balance', value: `${targetUser.credits}`, inline: true },
      { name: 'Updated By', value: req.user.username, inline: true }
    ]
  );

  res.json({
    success: true,
    message: `Credits updated for ${targetUser.username}. New Balance: ${targetUser.credits}`,
    user: {
      id: targetUser.id,
      username: targetUser.username,
      credits: targetUser.credits
    }
  });
});

// Whitelist UID (Pushes to local DB AND GTC API)
app.post('/api/whitelist/add', authenticateToken, async (req, res) => {
  const { uid, days } = req.body;

  if (!uid || !/^\d+$/.test(uid)) {
    return res.status(400).json({ success: false, message: 'UID must contain numeric digits only.' });
  }

  const durationDays = parseInt(days) || 30;
  const db = loadDB();
  const currentUser = db.users.find(u => u.id === req.user.id || u.username.toLowerCase() === req.user.username.toLowerCase());

  if (!currentUser) {
    return res.status(404).json({ success: false, message: 'User account not found.' });
  }

  const creditCost = 1;

  if (currentUser.role !== 'ADMIN') {
    if (currentUser.credits < creditCost) {
      return res.status(400).json({
        success: false,
        message: `Insufficient UID Credits! Required: ${creditCost}, Available: ${currentUser.credits}`
      });
    }
    currentUser.credits -= creditCost;
  }

  // 1. Push to External GTC API
  const { data: gtcData, error: gtcErr } = await callGtcApi('add', {}, { account_id: uid, for_days: durationDays });

  if (gtcErr) {
    console.warn(`[GTC API Warning] ${gtcErr}`);
  }

  // 2. Save locally
  let existingIndex = db.whitelists.findIndex(item => item.account_id === uid);
  const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);
  const expiryStr = (gtcData && gtcData.data && gtcData.data.expiry_date) || getExpiryDate(durationDays);

  const whitelistRecord = {
    account_id: uid,
    for_days: durationDays,
    adder_admin: currentUser.username,
    added_time: nowStr,
    expiry_date: expiryStr
  };

  if (existingIndex >= 0) {
    db.whitelists[existingIndex] = whitelistRecord;
  } else {
    db.whitelists.push(whitelistRecord);
  }

  saveDB(db);

  // Send Discord Audit Log
  sendDiscordWebhook(
    '⚡ UID Whitelisted',
    `UID **${uid}** whitelisted for **${durationDays} Days** by **${currentUser.username}** (${currentUser.role}).`,
    0x10B981,
    [
      { name: 'Target UID', value: `\`${uid}\``, inline: true },
      { name: 'Duration', value: `${durationDays} Days`, inline: true },
      { name: 'Whitelisted By', value: `${currentUser.username} (${currentUser.role})`, inline: true },
      { name: 'Expires On', value: whitelistRecord.expiry_date, inline: true }
    ]
  );

  res.json({
    success: true,
    message: `UID ${uid} Whitelisted successfully for ${durationDays} Days!`,
    data: whitelistRecord,
    remainingCredits: currentUser.credits
  });
});

// Whitelist UID (Remove from local DB)
app.post('/api/whitelist/remove', authenticateToken, async (req, res) => {
  const { uid } = req.body;

  if (!uid) {
    return res.status(400).json({ success: false, message: 'UID required.' });
  }

  const db = loadDB();
  const existingRecord = db.whitelists.find(item => item.account_id === uid);

  if (!existingRecord) {
    return res.status(404).json({ success: false, message: 'UID not found in database.' });
  }

  // Permission check: ADMIN can remove any; Seller/Reseller can only remove UIDs added by themselves
  if (req.user.role !== 'ADMIN' && existingRecord.adder_admin !== req.user.username) {
    return res.status(403).json({
      success: false,
      message: `Access Denied: You can ONLY remove UIDs created by your account (${req.user.username}).`
    });
  }

  // 1. Push Remove to GTC API
  const { data: gtcData, error: gtcErr } = await callGtcApi('remove', {}, { account_id: uid });
  if (gtcErr) {
    console.warn(`[GTC API Remove Warning] ${gtcErr}`);
  }

  // 2. Remove locally
  db.whitelists = db.whitelists.filter(item => item.account_id !== uid);
  saveDB(db);

  // Send Discord Audit Log
  sendDiscordWebhook(
    '🗑️ UID Whitelist Removed',
    `Whitelist access for UID **${uid}** was revoked by **${req.user.username}** (${req.user.role}).`,
    0xEF4444,
    [
      { name: 'Removed UID', value: `\`${uid}\``, inline: true },
      { name: 'Originally Added By', value: existingRecord.adder_admin, inline: true },
      { name: 'Removed By', value: `${req.user.username} (${req.user.role})`, inline: true }
    ]
  );

  res.json({
    success: true,
    message: `UID ${uid} removed from Whitelist successfully!`
  });
});

// Get Whitelist List
app.get('/api/whitelist/list', authenticateToken, (req, res) => {
  const db = loadDB();
  res.json({
    success: true,
    whitelists: db.whitelists
  });
});

// Public Client Whitelist Check Endpoint Alias
app.get('/api/client/check/:uid', (req, res) => {
  const { uid } = req.params;
  if (!uid || !/^\d+$/.test(uid)) {
    return res.status(400).json({ success: false, isWhitelisted: false, message: 'Invalid UID format.' });
  }

  const db = loadDB();
  const record = (db.whitelists || []).find(w => w.account_id === uid);

  if (!record) {
    return res.json({ success: false, isWhitelisted: false, message: 'UID not found in whitelist registry.' });
  }

  // Check expiry
  const now = new Date();
  const expiry = new Date(record.expiry_date.replace(' ', 'T'));
  const isExpired = isNaN(expiry.getTime()) ? false : expiry < now;
  const daysLeft = isNaN(expiry.getTime()) ? record.for_days : Math.max(0, Math.ceil((expiry - now) / (1000 * 60 * 60 * 24)));

  res.json({
    success: true,
    isWhitelisted: !isExpired,
    valid: !isExpired,
    uid: record.account_id,
    days: record.for_days,
    added_by: record.adder_admin,
    added_time: record.added_time,
    expiry_date: record.expiry_date,
    days_remaining: daysLeft,
    expired: isExpired,
    data: {
      account_id: record.account_id,
      for_days: record.for_days,
      adder_admin: record.adder_admin,
      added_time: record.added_time,
      expiry_date: record.expiry_date,
      status: isExpired ? 'EXPIRED' : 'ACTIVE'
    }
  });
});

// ----------------------------------------------------
// API USER & THIRD-PARTY INTEGRATION ENDPOINTS
// ----------------------------------------------------

// API User Login Endpoint (Supports Username & Password OR API Key login)
app.post('/api/api-user/login', async (req, res) => {
  const { username, password, api_key } = req.body;
  const db = loadDB();

  let user = null;

  if (api_key) {
    user = db.users.find(u => u.api_key === api_key.trim());
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid API Key' });
    }
  } else if (username && password) {
    user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
  } else {
    return res.status(400).json({ success: false, message: 'Username & Password OR API Key is required' });
  }

  // Ensure user has API Key
  if (!user.api_key) {
    user.api_key = generateApiKey();
    saveDB(db);
  }

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role, api_key: user.api_key },
    JWT_SECRET,
    { expiresIn: '30d' }
  );

  return res.json({
    success: true,
    message: 'API User authentication successful',
    token: token,
    apiKey: user.api_key,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      credits: user.credits,
      api_key: user.api_key
    }
  });
});

// Get Current API User Profile & Whitelist Records
app.get('/api/api-user/me', authenticateToken, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.user.id || u.username.toLowerCase() === req.user.username.toLowerCase());
  if (!user) {
    return res.status(404).json({ success: false, message: 'User account not found' });
  }

  const myWhitelists = db.whitelists.filter(w => w.adder_admin === user.username);

  res.json({
    success: true,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      credits: user.credits,
      api_key: user.api_key
    },
    whitelists: myWhitelists
  });
});

// Reset / Regenerate API Key Endpoint
app.post('/api/api-user/reset-key', authenticateToken, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.user.id || u.username.toLowerCase() === req.user.username.toLowerCase());
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }

  user.api_key = generateApiKey();
  saveDB(db);

  sendDiscordWebhook(
    '🔑 API Key Regenerated',
    `API User **${user.username}** regenerated their API Key.`,
    0xF59E0B,
    [
      { name: 'User', value: user.username, inline: true },
      { name: 'Role', value: user.role, inline: true }
    ]
  );

  res.json({
    success: true,
    message: 'API Key reset successfully!',
    apiKey: user.api_key
  });
});

// Reset All Whitelist Data Endpoint (For API User)
app.post('/api/api-user/reset-data', authenticateToken, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.user.id || u.username.toLowerCase() === req.user.username.toLowerCase());
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }

  const removedCount = db.whitelists.filter(w => w.adder_admin === user.username).length;
  db.whitelists = db.whitelists.filter(w => w.adder_admin !== user.username);
  saveDB(db);

  res.json({
    success: true,
    message: `Reset complete! Removed ${removedCount} whitelist records associated with user ${user.username}.`
  });
});

// ----------------------------------------------------
// EXTERNAL THIRD-PARTY API ENDPOINTS (v1)
// (Matches GTC API style push/remove/check behavior)
// ----------------------------------------------------

// 1. Add / Push Whitelist via API Key (Syncs locally AND pushes to GTC API)
app.post(['/api/v1/whitelist/add', '/api/external/whitelist/add'], authenticateApiKey, async (req, res) => {
  const uid = req.body.account_id || req.body.uid || req.query.account_id || req.query.uid;
  const days = req.body.for_days || req.body.days || req.query.for_days || req.query.days || 30;

  if (!uid || !/^\d+$/.test(String(uid).trim())) {
    return res.status(400).json({ success: false, message: 'Numeric account_id / uid parameter is required.' });
  }

  const cleanUid = String(uid).trim();
  const durationDays = parseInt(days) || 30;
  const db = loadDB();
  const user = req.user;

  if (user.role !== 'ADMIN') {
    if (user.credits < 1) {
      return res.status(400).json({ success: false, message: 'Insufficient UID Credits.' });
    }
    user.credits -= 1;
  }

  // Push to GTC API
  const { data: gtcData, error: gtcErr } = await callGtcApi('add', {}, { account_id: cleanUid, for_days: durationDays });

  const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);
  const expiryStr = (gtcData && gtcData.data && gtcData.data.expiry_date) || getExpiryDate(durationDays);

  const whitelistRecord = {
    account_id: cleanUid,
    for_days: durationDays,
    adder_admin: user.username,
    added_time: nowStr,
    expiry_date: expiryStr
  };

  let existingIndex = db.whitelists.findIndex(item => item.account_id === cleanUid);
  if (existingIndex >= 0) {
    db.whitelists[existingIndex] = whitelistRecord;
  } else {
    db.whitelists.push(whitelistRecord);
  }

  saveDB(db);

  return res.json({
    success: true,
    message: `UID ${cleanUid} whitelisted successfully for ${durationDays} days via API!`,
    data: whitelistRecord,
    remaining_credits: user.credits,
    gtc_synced: !gtcErr
  });
});

// 2. Remove Whitelist via API Key (Removes locally AND from GTC API)
app.post(['/api/v1/whitelist/remove', '/api/external/whitelist/remove'], authenticateApiKey, async (req, res) => {
  const uid = req.body.account_id || req.body.uid || req.query.account_id || req.query.uid;

  if (!uid) {
    return res.status(400).json({ success: false, message: 'account_id or uid required.' });
  }

  const cleanUid = String(uid).trim();
  const db = loadDB();
  const user = req.user;

  const existing = db.whitelists.find(w => w.account_id === cleanUid);
  if (!existing) {
    return res.status(404).json({ success: false, message: 'UID not found in database.' });
  }

  if (user.role !== 'ADMIN' && existing.adder_admin !== user.username) {
    return res.status(403).json({ success: false, message: 'Access Denied: You can only remove UIDs created by your API Key.' });
  }

  await callGtcApi('remove', {}, { account_id: cleanUid });

  db.whitelists = db.whitelists.filter(w => w.account_id !== cleanUid);
  saveDB(db);

  return res.json({
    success: true,
    message: `UID ${cleanUid} removed from Whitelist successfully!`
  });
});

// 3. Check Whitelist Status via API Key
app.get(['/api/v1/whitelist/check/:uid', '/api/external/whitelist/check/:uid'], authenticateApiKey, (req, res) => {
  const { uid } = req.params;
  const db = loadDB();
  const record = (db.whitelists || []).find(w => w.account_id === uid);

  if (!record) {
    return res.json({ success: false, isWhitelisted: false, message: 'UID not whitelisted.' });
  }

  const now = new Date();
  const expiry = new Date(record.expiry_date.replace(' ', 'T'));
  const isExpired = isNaN(expiry.getTime()) ? false : expiry < now;

  return res.json({
    success: true,
    isWhitelisted: !isExpired,
    account_id: record.account_id,
    for_days: record.for_days,
    expiry_date: record.expiry_date,
    adder_admin: record.adder_admin,
    status: isExpired ? 'EXPIRED' : 'ACTIVE'
  });
});

// Global Anti-Crash Protection Handlers
process.on('uncaughtException', (err) => {
  console.error('[ANTI-CRASH] Uncaught Exception caught:', err.message || err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('[ANTI-CRASH] Unhandled Promise Rejection at:', promise, 'reason:', reason);
});

// Start Express API Server
app.listen(PORT, () => {
  console.log(`===================================================`);
  console.log(`🚀 UID Whitelist Backend API active on Port: ${PORT}`);
  console.log(`📡 GTC API Endpoint: ${GTC_API_URL}`);
  console.log(`🛡️ Anti-Crash Protection: ACTIVE`);
  console.log(`===================================================`);
});

