import fs from 'fs';
import path from 'path';
import bcrypt from 'bcryptjs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Allow persistent disk storage directory via env var DATA_DIR (e.g. Render persistent disk /var/data)
const DATA_DIR = process.env.DATA_DIR || __dirname;

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_FILE = path.join(DATA_DIR, 'database.json');
const BACKUP_FILE = path.join(DATA_DIR, 'database_backup.json');

const initialData = {
  users: [],
  whitelists: [],
  login_history: []
};

export function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    // Check if backup exists
    if (fs.existsSync(BACKUP_FILE)) {
      try {
        const backupData = fs.readFileSync(BACKUP_FILE, 'utf8');
        saveDB(JSON.parse(backupData));
        console.log('[DB] Restored database from backup file.');
        return JSON.parse(backupData);
      } catch (e) {
        console.error('Failed to restore backup:', e);
      }
    }
    saveDB(initialData);
  }
  try {
    const data = fs.readFileSync(DB_FILE, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    console.error('Error reading DB, restoring from backup if available:', err);
    if (fs.existsSync(BACKUP_FILE)) {
      try {
        const backupData = fs.readFileSync(BACKUP_FILE, 'utf8');
        return JSON.parse(backupData);
      } catch (e) {}
    }
    saveDB(initialData);
    return initialData;
  }
}

export function saveDB(data) {
  try {
    const jsonStr = JSON.stringify(data, null, 2);
    fs.writeFileSync(DB_FILE, jsonStr, 'utf8');
    // Save backup copy simultaneously to prevent data corruption/loss
    fs.writeFileSync(BACKUP_FILE, jsonStr, 'utf8');
  } catch (err) {
    console.error('Error saving DB:', err);
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
