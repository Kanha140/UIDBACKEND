# UID Bypass Backend API (Node.js + JSON Database)

This is the primary Node.js Express REST API backend for **UID Bypass Registry V4.0**.
It uses `database.json` for persistent storage and connects to the GTC API for live whitelist sync.

---

## ⚡ Deployment Instructions for Render.com

### Step 1: Connect Repository to Render
1. Log in to [Render Dashboard](https://dashboard.render.com).
2. Click **New +** → **Web Service**.
3. Connect your GitHub repository (`KANHA/UIDBYPASSBACK` or your backend repo).

### Step 2: Build & Deployment Settings
- **Name**: `uidbackend` (or any custom name)
- **Environment**: `Node`
- **Region**: `Oregon (US West)` or closest region
- **Branch**: `main`
- **Root Directory**: *(Leave Empty / Blank)*
- **Build Command**: `npm install`
- **Start Command**: `npm start`

### Step 3: Environment Variables
Add the following Environment Variables under **Advanced**:
- `JWT_SECRET`: `UID_BYPASS_SUPER_SECRET_KEY_2026`
- `API_URL`: `https://gtccheats.xyz/Api/uidbypassapi/api_user.php`
- `API_KEY`: `GTCAPI-0E9C83D81E2942CACE91A4AF6C86313E`
- `DATA_DIR`: `/var/data` (optional for Render Disk)

### Step 4: Disk Volume (Data Preservation)
To ensure user accounts, credits, and whitelists are **NEVER erased** when Render restarts:
- Click **Disks → Add Disk**.
- **Name**: `uid_data_disk`
- **Mount Path**: `/var/data`
- **Size**: `1 GB`

---

## 📡 Live API Endpoints
- `GET /api/health` — Health check
- `POST /api/auth/login` — User authentication & IP tracking
- `GET /api/client/check/:uid` — Public Client Portal UID status check
- `POST /api/whitelist/add` — Add UID & Sync to GTC API
- `POST /api/whitelist/remove` — Remove UID & Sync to GTC API
