import http.server
import socketserver
import json
import urllib.request
import urllib.parse
import os
import hashlib
import time
from datetime import datetime, timedelta

PORT = 5000
GTC_API_URL = 'https://gtccheats.xyz/Api/uidbypassapi/api_user.php'
GTC_API_KEY = 'GTCAPI-0E9C83D81E2942CACE91A4AF6C86313E'
DB_FILE = os.path.join(os.path.dirname(__file__), 'database.json')

# Helper: Load/Save JSON DB
def load_db():
    if not os.path.exists(DB_FILE):
        save_db({'users': [], 'whitelists': []})
    try:
        with open(DB_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        data = {'users': [], 'whitelists': []}
        save_db(data)
        return data

def save_db(data):
    with open(DB_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

def hash_pw(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def init_db():
    db = load_db()
    admin = next((u for u in db['users'] if u['username'].upper() == 'KANHA'), None)
    if not admin:
        db['users'].append({
            'id': 'usr_admin1',
            'username': 'KANHA',
            'password_hash': hash_pw('KANHA641412'),
            'role': 'ADMIN',
            'created_by': 'SYSTEM',
            'credits': 999999,
            'created_at': datetime.now().isoformat()
        })
        save_db(db)
        print("[DB] Master Admin account KANHA initialized.")

# Call External GTC API (Temporarily bypassed)
def call_gtc_api(action, query_params=None, body_data=None):
    # Temporarily disabled external GTC API call as requested
    return {'success': True, 'message': 'GTC API Bypassed', 'data': body_data}, None

init_db()

class RESTRequestHandler(http.server.BaseHTTPRequestHandler):
    def _send_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-KEY')

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def _respond(self, status_code, body_dict):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(body_dict).encode('utf-8'))

    def _get_auth_user(self):
        auth_header = self.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None
        token = auth_header.split(' ')[1]
        try:
            # Token format: username:role:id
            parts = token.split(':')
            if len(parts) >= 3:
                return {'username': parts[0], 'role': parts[1], 'id': parts[2]}
        except Exception:
            pass
        return None

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Health Check
        if path == '/api/health':
            return self._respond(200, {'status': 'ONLINE', 'message': 'Python REST API Active'})

        # Public Whitelist Verification Check
        if path.startswith('/api/whitelist/check/'):
            uid = path.split('/')[-1]
            db = load_db()
            entry = next((item for item in db['whitelists'] if item['account_id'] == uid), None)
            
            # Sync check with GTC API
            gtc_res, _ = call_gtc_api('info', {'account_id': uid})
            if gtc_res and gtc_res.get('success') and gtc_res.get('data'):
                d = gtc_res['data']
                entry = {
                    'account_id': d['account_id'],
                    'for_days': d['for_days'],
                    'adder_admin': d.get('adder_admin', 'API_ADMIN'),
                    'added_time': d.get('added_time', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                    'expiry_date': d['expiry_date']
                }

            if not entry:
                return self._respond(200, {'success': False, 'isWhitelisted': False, 'message': 'UID is NOT Whitelisted.'})

            try:
                exp_dt = datetime.strptime(entry['expiry_date'].split('.')[0], '%Y-%m-%d %H:%M:%S')
                is_expired = exp_dt < datetime.now()
            except Exception:
                is_expired = False

            return self._respond(200, {
                'success': True,
                'isWhitelisted': not is_expired,
                'data': {
                    'account_id': entry['account_id'],
                    'for_days': entry['for_days'],
                    'adder_admin': entry['adder_admin'],
                    'added_time': entry['added_time'],
                    'expiry_date': entry['expiry_date'],
                    'status': 'EXPIRED' if is_expired else 'ACTIVE'
                }
            })

        # Protected Endpoints
        user = self._get_auth_user()
        if not user:
            if path in ['/api/auth/me', '/api/users', '/api/whitelist/list']:
                return self._respond(401, {'success': False, 'message': 'Access token required.'})

        if path == '/api/auth/me':
            db = load_db()
            db_user = next((u for u in db['users'] if u['id'] == user['id']), None)
            if not db_user:
                return self._respond(404, {'success': False, 'message': 'User not found'})
            return self._respond(200, {
                'success': True,
                'user': {
                    'id': db_user['id'],
                    'username': db_user['username'],
                    'role': db_user['role'],
                    'credits': db_user['credits']
                }
            })

        if path == '/api/users':
            db = load_db()
            filtered = []
            if user['role'] == 'ADMIN':
                filtered = [{'id': u['id'], 'username': u['username'], 'role': u['role'], 'credits': u['credits'], 'created_by': u['created_by'], 'created_at': u['created_at']} for u in db['users']]
            elif user['role'] == 'SELLER':
                filtered = [{'id': u['id'], 'username': u['username'], 'role': u['role'], 'credits': u['credits'], 'created_by': u['created_by'], 'created_at': u['created_at']} for u in db['users'] if u['created_by'] == user['username'] or u['role'] == 'RESELLER']
            return self._respond(200, {'success': True, 'users': filtered})

        if path == '/api/whitelist/list':
            db = load_db()
            return self._respond(200, {'success': True, 'whitelists': db['whitelists']})

        return self._respond(404, {'error': 'Not Found'})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        content_len = int(self.headers.get('Content-Length', 0))
        body_bytes = self.rfile.read(content_len) if content_len > 0 else b'{}'
        try:
            body = json.loads(body_bytes.decode('utf-8'))
        except Exception:
            body = {}

        # Login Endpoint
        if path == '/api/auth/login':
            username = body.get('username', '').strip()
            password = body.get('password', '').strip()

            db = load_db()
            db_user = next((u for u in db['users'] if u['username'].lower() == username.lower()), None)

            if not db_user or db_user['password_hash'] != hash_pw(password):
                return self._respond(401, {'success': False, 'message': 'Invalid credentials'})

            token = f"{db_user['username']}:{db_user['role']}:{db_user['id']}"

            return self._respond(200, {
                'success': True,
                'token': token,
                'user': {
                    'id': db_user['id'],
                    'username': db_user['username'],
                    'role': db_user['role'],
                    'credits': db_user['credits']
                }
            })

        # Protected Post Operations
        user = self._get_auth_user()
        if not user:
            return self._respond(401, {'success': False, 'message': 'Access token required.'})

        # Create User
        if path == '/api/users/create':
            username = body.get('username', '').strip()
            password = body.get('password', '').strip()
            role = body.get('role', '').upper()
            initial_credits = int(body.get('initialCredits', 0))

            if user['role'] == 'ADMIN' and role not in ['SELLER', 'RESELLER']:
                return self._respond(400, {'success': False, 'message': 'Admin can only create SELLER or RESELLER.'})
            if user['role'] == 'SELLER' and role != 'RESELLER':
                return self._respond(403, {'success': False, 'message': 'Sellers can ONLY create RESELLERS.'})

            db = load_db()
            if any(u['username'].lower() == username.lower() for u in db['users']):
                return self._respond(400, {'success': False, 'message': 'Username already exists.'})

            new_u = {
                'id': f'usr_{int(time.time()*1000)}',
                'username': username,
                'password_hash': hash_pw(password),
                'role': role,
                'created_by': user['username'],
                'credits': initial_credits,
                'created_at': datetime.now().isoformat()
            }
            db['users'].append(new_u)
            save_db(db)
            return self._respond(200, {'success': True, 'message': f'{role} account created successfully!'})

        # Update Credits
        if path == '/api/users/credits':
            target_id = body.get('userId')
            amount = int(body.get('amount', 0))
            action = body.get('action', 'ADD')

            db = load_db()
            target_user = next((u for u in db['users'] if u['id'] == target_id), None)

            if not target_user:
                return self._respond(404, {'success': False, 'message': 'Target user not found'})

            if action == 'ADD':
                target_user['credits'] += amount
            else:
                target_user['credits'] = amount

            save_db(db)
            return self._respond(200, {'success': True, 'message': f'Credits updated for {target_user["username"]}. Total: {target_user["credits"]}'})

        # Add Whitelist UID
        if path == '/api/whitelist/add':
            uid = body.get('uid', '').strip()
            days = int(body.get('days', 30))

            if not uid.isdigit():
                return self._respond(400, {'success': False, 'message': 'UID must contain numeric digits only.'})

            db = load_db()
            db_user = next((u for u in db['users'] if u['id'] == user['id']), None)

            if db_user and db_user['role'] != 'ADMIN':
                if db_user['credits'] < 1:
                    return self._respond(400, {'success': False, 'message': 'Insufficient credits! 1 credit required.'})
                db_user['credits'] -= 1

            # Push to GTC API
            gtc_res, gtc_err = call_gtc_api('add', query_params={}, body_data={'account_id': uid, 'for_days': days})

            now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            exp_str = (datetime.now() + timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
            if gtc_res and gtc_res.get('data') and gtc_res['data'].get('expiry_date'):
                exp_str = gtc_res['data']['expiry_date']

            record = {
                'account_id': uid,
                'for_days': days,
                'adder_admin': user['username'],
                'added_time': now_str,
                'expiry_date': exp_str
            }

            db['whitelists'] = [w for w in db['whitelists'] if w['account_id'] != uid]
            db['whitelists'].append(record)
            save_db(db)

            return self._respond(200, {
                'success': True,
                'message': f'UID {uid} Whitelisted for {days} Days and Pushed to GTC API!',
                'data': record,
                'gtcResponse': gtc_res
            })

        # Remove Whitelist UID
        if path == '/api/whitelist/remove':
            uid = body.get('uid', '').strip()
            gtc_res, _ = call_gtc_api('remove', query_params={}, body_data={'account_id': uid})

            db = load_db()
            db['whitelists'] = [w for w in db['whitelists'] if w['account_id'] != uid]
            save_db(db)

            return self._respond(200, {
                'success': True,
                'message': f'UID {uid} removed from Whitelist and GTC API!',
                'gtcResponse': gtc_res
            })

        return self._respond(404, {'error': 'Not Found'})

if __name__ == '__main__':
    with socketserver.TCPServer(('', PORT), RESTRequestHandler) as httpd:
        print(f"===================================================")
        print(f"🚀 Python REST API Backend Running on Port {PORT}")
        print(f"📡 Master Admin KANHA Seeded.")
        print(f"===================================================")
        httpd.serve_forever()
