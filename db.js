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

export async function initDB() {
  const db = loadDB();
  
  // Ensure Master Admin KANHA exists
  let admin = db.users.find(u => u.username.toUpperCase() === 'KANHA');
  if (!admin) {
    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash('KANHA641412', salt);
    admin = {
      id: 'admin-1',
      username: 'KANHA',
      password_hash: password_hash,
      role: 'ADMIN',
      created_by: 'SYSTEM',
      credits: 999999,
      created_at: new Date().toISOString()
    };
    db.users.push(admin);
    saveDB(db);
    console.log('[DB] Master Admin account KANHA initialized.');
  } else {
    // Ensure password matches requested reset if needed
    const isMatch = await bcrypt.compare('KANHA641412', admin.password_hash);
    if (!isMatch) {
      const salt = await bcrypt.genSalt(10);
      admin.password_hash = await bcrypt.hash('KANHA641412', salt);
      saveDB(db);
      console.log('[DB] Master Admin password updated to KANHA641412.');
    }
  }
}
