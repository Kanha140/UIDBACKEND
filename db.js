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

  // Try reading main DB file
  if (fs.existsSync(DB_FILE)) {
    try {
      const raw = fs.readFileSync(DB_FILE, 'utf8');
      fileData = JSON.parse(raw);
    } catch (e) {
      console.error('[DB LOAD ERROR] Main file error:', e.message);
    }
  }

  // Try backup file if main file failed
  if (!fileData && fs.existsSync(BACKUP_FILE)) {
    try {
      const rawBackup = fs.readFileSync(BACKUP_FILE, 'utf8');
      fileData = JSON.parse(rawBackup);
    } catch (e) {
      console.error('[DB BACKUP LOAD ERROR] Backup file error:', e.message);
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
  try {
    const jsonStr = JSON.stringify(data, null, 2);
    const tmpFile = DB_FILE + '.tmp';
    const tmpBackup = BACKUP_FILE + '.tmp';

    // Atomic write for main database file
    fs.writeFileSync(tmpFile, jsonStr, 'utf8');
    fs.renameSync(tmpFile, DB_FILE);

    // Atomic write for backup database file
    fs.writeFileSync(tmpBackup, jsonStr, 'utf8');
    fs.renameSync(tmpBackup, BACKUP_FILE);
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
