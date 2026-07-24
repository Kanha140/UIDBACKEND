import fs from 'fs';
import path from 'path';
import bcrypt from 'bcryptjs';
import { fileURLToPath } from 'url';
import { PERMANENT_STORE } from './storage.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DATA_DIR = process.env.DATA_DIR || __dirname;

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_FILE = path.join(DATA_DIR, 'database.json');
const BACKUP_FILE = path.join(DATA_DIR, 'database_backup.json');

// In-Memory Database Cache in JS (Persists across function calls during uptime)
let memoryDB = null;

export function loadDB() {
  if (memoryDB) {
    return memoryDB;
  }

  let fileData = null;

  // Search candidate paths in order of priority
  const searchPaths = [
    DB_FILE,
    BACKUP_FILE,
    path.join(__dirname, 'database.json'),
    path.join(__dirname, 'database_backup.json'),
    '/tmp/uid_database.json'
  ];

  for (const filePath of searchPaths) {
    if (fs.existsSync(filePath)) {
      try {
        const raw = fs.readFileSync(filePath, 'utf8');
        const parsed = JSON.parse(raw);
        if (parsed && Array.isArray(parsed.users) && parsed.users.length > 0) {
          fileData = parsed;
          console.log(`[DB LOAD] Database loaded successfully from: ${filePath}`);
          break;
        }
      } catch (e) {
        console.error(`[DB LOAD WARN] Error reading ${filePath}:`, e.message);
      }
    }
  }

  // Try environment variable fallback if set (e.g. PERSIST_DB_JSON on Render)
  if (!fileData && process.env.PERSIST_DB_JSON) {
    try {
      const decoded = Buffer.from(process.env.PERSIST_DB_JSON, 'base64').toString('utf8');
      fileData = JSON.parse(decoded);
      console.log('[DB LOAD] Database loaded from PERSIST_DB_JSON environment variable.');
    } catch (e) {
      try {
        fileData = JSON.parse(process.env.PERSIST_DB_JSON);
      } catch (err) {}
    }
  }

  // If no file data exists, fallback to PERMANENT_STORE JS module
  if (!fileData) {
    fileData = JSON.parse(JSON.stringify(PERMANENT_STORE));
  }

  // Ensure arrays exist
  if (!fileData.users) fileData.users = [];
  if (!fileData.whitelists) fileData.whitelists = [];
  if (!fileData.login_history) fileData.login_history = [];

  // Merge permanent seeded users from storage.js if missing
  for (const pUser of PERMANENT_STORE.users) {
    if (!fileData.users.some(u => u.username.toLowerCase() === pUser.username.toLowerCase())) {
      fileData.users.push(pUser);
    }
  }

  // Merge permanent whitelists from storage.js if missing
  for (const pWhite of PERMANENT_STORE.whitelists) {
    if (!fileData.whitelists.some(w => w.account_id === pWhite.account_id)) {
      fileData.whitelists.push(pWhite);
    }
  }

  memoryDB = fileData;
  saveDB(memoryDB);
  return memoryDB;
}

export function saveDB(data) {
  memoryDB = data;
  
  // Sync in-memory PERMANENT_STORE
  PERMANENT_STORE.users = data.users || [];
  PERMANENT_STORE.whitelists = data.whitelists || [];
  PERMANENT_STORE.login_history = data.login_history || [];

  try {
    const jsonStr = JSON.stringify(data, null, 2);

    const targetPaths = [
      DB_FILE,
      BACKUP_FILE,
      path.join(__dirname, 'database.json'),
      path.join(__dirname, 'database_backup.json'),
      '/tmp/uid_database.json'
    ];

    for (const filePath of targetPaths) {
      try {
        const dir = path.dirname(filePath);
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }
        const tmpFile = filePath + '.tmp';
        fs.writeFileSync(tmpFile, jsonStr, 'utf8');
        fs.renameSync(tmpFile, filePath);
      } catch (e) {
        // Ignore unwritable path errors
      }
    }
  } catch (err) {
    console.error('[DB SAVE WARNING] Could not write to disk, data kept in memory:', err.message);
  }
}

export function generateApiKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let key = 'APIKEY-';
  for (let i = 0; i < 16; i++) {
    if (i > 0 && i % 4 === 0) key += '-';
    key += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return key;
}

export async function initDB() {
  const db = loadDB();
  const defaultPass = 'KANHA541412';
  const salt = await bcrypt.genSalt(10);
  const commonHash = await bcrypt.hash(defaultPass, salt);

  // Default Permanent Staff Accounts to guarantee NO DATA ERASURE on Render container restarts
  const defaultAccounts = [
    {
      id: 'admin-1',
      username: 'KANHA',
      role: 'ADMIN',
      created_by: 'SYSTEM',
      credits: 999999,
      api_key: 'APIKEY-MASTER-ADMIN-KANHA-2026'
    },
    {
      id: 'usr_seller_1',
      username: 'SELLER',
      role: 'SELLER',
      created_by: 'KANHA',
      credits: 500,
      api_key: 'APIKEY-SELLER-PRIMARY-2026'
    },
    {
      id: 'usr_reseller_1',
      username: 'RESELLER',
      role: 'RESELLER',
      created_by: 'SELLER',
      credits: 100,
      api_key: 'APIKEY-RESELLER-PRIMARY-2026'
    },
    {
      id: 'usr_apiseller_1',
      username: 'API_SELLER',
      role: 'API_SELLER',
      created_by: 'KANHA',
      credits: 500,
      api_key: 'APIKEY-APISELLER-PRIMARY-2026'
    },
    {
      id: 'usr_apiuser_1',
      username: 'API_USER',
      role: 'API_USER',
      created_by: 'API_SELLER',
      credits: 1000,
      api_key: 'APIKEY-BR5V-IOHS-LTOJ-0ZFN'
    }
  ];

  let saveNeeded = false;

  for (const defAcc of defaultAccounts) {
    let existing = db.users.find(u => u.username.toLowerCase() === defAcc.username.toLowerCase());
    if (!existing) {
      db.users.push({
        id: defAcc.id,
        username: defAcc.username,
        password_hash: commonHash,
        role: defAcc.role,
        created_by: defAcc.created_by,
        credits: defAcc.credits,
        api_key: defAcc.api_key,
        created_at: new Date().toISOString(),
        last_login_ip: '127.0.0.1'
      });
      saveNeeded = true;
      console.log(`[DB INIT] Default account created: ${defAcc.username} (${defAcc.role})`);
    } else {
      // Ensure API key format
      if (!existing.api_key || existing.api_key.startsWith('UIDKEY-')) {
        existing.api_key = defAcc.api_key;
        saveNeeded = true;
      }
      // Ensure password support for KANHA541412
      const isMatch = await bcrypt.compare(defaultPass, existing.password_hash);
      if (!isMatch) {
        existing.password_hash = commonHash;
        saveNeeded = true;
      }
    }
  }

  // Ensure all existing users have an api_key with APIKEY- prefix
  for (const user of db.users) {
    if (!user.api_key) {
      user.api_key = generateApiKey();
      saveNeeded = true;
    } else if (user.api_key.startsWith('UIDKEY-')) {
      user.api_key = user.api_key.replace(/^UIDKEY-/, 'APIKEY-');
      saveNeeded = true;
    }
  }

  if (saveNeeded) {
    saveDB(db);
  }
}
