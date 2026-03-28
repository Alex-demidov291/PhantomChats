import base64
import datetime
import hashlib
import io
import json
import os
import queue
import sqlite3
import threading
import time
import uuid
from collections import defaultdict

import opaque_ke_py
from PIL import Image
from flask import Flask, request, jsonify, Response, stream_with_context
import settings


def adapt_datetime(dt):
    return dt.isoformat()


sqlite3.register_adapter(datetime.datetime, adapt_datetime)

SERVER_HOST = settings.SERVER_HOST
SERVER_PORT = settings.RUNNING_PORT
TOKEN_LIFETIME = 86400
app = Flask(__name__)

SESSION_HASH_SALT = settings.SESSION_HASH_SALT.encode()

SERVER_SETUP_FILE = "server_setup.bin"
if os.path.exists(SERVER_SETUP_FILE):
    with open(SERVER_SETUP_FILE, "rb") as f:
        SERVER_SETUP_BYTES = f.read()
else:
    SERVER_SETUP_BYTES = opaque_ke_py.server_setup().to_bytes()
    with open(SERVER_SETUP_FILE, "wb") as f:
        f.write(SERVER_SETUP_BYTES)

request_log = defaultdict(list)
request_lock = threading.Lock()
RATE_LIMIT = 7
RATE_PERIOD = 1
BLOCK_ATTEMPTS = 8
BLOCK_DURATION = 3600


def rate_limit(f):
    def decorated(*args, **kwargs):
        device_id = request.headers.get('X-Device-ID')
        if not device_id:
            return jsonify({'success': False, 'error': 'Device ID required'}), 400
        now = time.time()
        with request_lock:
            request_log[device_id] = [t for t in request_log[device_id] if now - t < RATE_PERIOD]
            if len(request_log[device_id]) >= RATE_LIMIT:
                return jsonify({'success': False, 'error': 'Too many requests'}), 429
            request_log[device_id].append(now)
        return f(*args, **kwargs)

    decorated.__name__ = f.__name__
    return decorated


class Database:
    def __init__(self, db_path='messenger.db'):
        self.db_path = db_path
        self.init_db()
        self.start_cleanup_thread()
        self.start_status_cleanup_thread()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                login TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                user_id INTEGER UNIQUE,
                avatar_version INTEGER DEFAULT 0,
                opaque_password_file BLOB NOT NULL,
                e2ee_salt TEXT,
                encrypted_master_key TEXT,
                master_key_salt TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_login TEXT NOT NULL,
                receiver_login TEXT NOT NULL,
                message_text TEXT NOT NULL,
                has_file INTEGER DEFAULT 0,
                file_id INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                client_timestamp TEXT,
                nonce TEXT,
                FOREIGN KEY (sender_login) REFERENCES users (login),
                FOREIGN KEY (receiver_login) REFERENCES users (login),
                FOREIGN KEY (file_id) REFERENCES files(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT NOT NULL,
                file_type TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                file_data BLOB NOT NULL,
                thumbnail_data BLOB,
                uploaded_by TEXT NOT NULL,
                uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_image_only INTEGER DEFAULT 0,
                encrypted_key TEXT,
                nonce_file TEXT,
                nonce_thumbnail TEXT,
                is_encrypted INTEGER DEFAULT 0,
                FOREIGN KEY (uploaded_by) REFERENCES users(login)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contact_owner TEXT NOT NULL,
                contact_login TEXT NOT NULL,
                FOREIGN KEY (contact_owner) REFERENCES users(login),
                FOREIGN KEY (contact_login) REFERENCES users(login),
                UNIQUE(contact_owner, contact_login)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS contact_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_login TEXT NOT NULL,
                contact_login TEXT NOT NULL,
                display_name TEXT,
                FOREIGN KEY (user_login) REFERENCES users(login),
                FOREIGN KEY (contact_login) REFERENCES users(login),
                UNIQUE(user_login, contact_login)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                session_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                user_login TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(user_id),
                FOREIGN KEY (user_login) REFERENCES users(login)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cleanup_settings (
                user_id INTEGER PRIMARY KEY,
                cleanup_interval INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_avatars (
                user_id INTEGER PRIMARY KEY,
                avatar_data BLOB NOT NULL,
                file_size INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS opaque_login_states (
                state_id TEXT PRIMARY KEY,
                login TEXT NOT NULL,
                server_state BLOB NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                FOREIGN KEY (login) REFERENCES users(login)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login TEXT NOT NULL,
                device_id TEXT NOT NULL,
                attempts INTEGER DEFAULT 0,
                last_attempt TIMESTAMP,
                blocked_until TIMESTAMP,
                UNIQUE(login, device_id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_public_keys (
                user_id INTEGER PRIMARY KEY,
                public_key TEXT NOT NULL,
                signature TEXT NOT NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS used_nonces (
                nonce TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                expires_at DATETIME NOT NULL,
                PRIMARY KEY (nonce, user_id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_status (
                user_id INTEGER PRIMARY KEY,
                status TEXT DEFAULT 'offline',
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                current_device_id TEXT,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS active_connections (
                session_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_ping DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_online INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')
        conn.commit()
        conn.close()

    def start_cleanup_thread(self):
        def cleanup_worker():
            while True:
                time.sleep(300)
                self.cleanup_expired_sessions()
                self.cleanup_used_nonces()

        thread = threading.Thread(target=cleanup_worker, daemon=True)
        thread.start()

    def start_status_cleanup_thread(self):
        def status_cleanup_worker():
            while True:
                time.sleep(60)
                self.cleanup_offline_connections()

        thread = threading.Thread(target=status_cleanup_worker, daemon=True)
        thread.start()

    def cleanup_expired_sessions(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT DISTINCT user_id FROM user_sessions 
            WHERE expires_at < datetime('now') AND is_active = 1
        ''')
        expired_users = cursor.fetchall()
        for user in expired_users:
            user_id = user[0]
            cursor.execute('SELECT cleanup_interval FROM cleanup_settings WHERE user_id = ?', (user_id,))
            cleanup = cursor.fetchone()
            if cleanup and cleanup[0] == 0:
                cursor.execute('DELETE FROM user_sessions WHERE user_id = ? AND expires_at < datetime("now")',
                               (user_id,))
            else:
                cursor.execute('''
                    UPDATE user_sessions SET is_active = 0 
                    WHERE user_id = ? AND expires_at < datetime("now")
                ''', (user_id,))
        conn.commit()
        conn.close()

    def cleanup_used_nonces(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM used_nonces WHERE expires_at < datetime('now')")
        conn.commit()
        conn.close()

    def cleanup_offline_connections(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE active_connections SET is_online = 0
            WHERE last_ping < datetime('now', '-60 seconds')
        ''')
        cursor.execute('''
            UPDATE user_status SET status = 'offline', last_seen = CURRENT_TIMESTAMP
            WHERE user_id IN (
                SELECT user_id FROM active_connections 
                WHERE is_online = 0 AND user_id NOT IN (
                    SELECT user_id FROM active_connections WHERE is_online = 1
                )
            )
        ''')
        conn.commit()
        conn.close()

    def get_login_attempt(self, login, device_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            'SELECT attempts, last_attempt, blocked_until FROM login_attempts WHERE login = ? AND device_id = ?',
            (login, device_id))
        row = cursor.fetchone()
        conn.close()
        if row:
            return dict(row)
        return None

    def increment_login_attempt(self, login, device_id):
        now = datetime.datetime.now().isoformat()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO login_attempts (login, device_id, attempts, last_attempt)
            VALUES (?, ?, 1, ?)
            ON CONFLICT(login, device_id) DO UPDATE SET
                attempts = attempts + 1,
                last_attempt = ?
        ''', (login, device_id, now, now))
        conn.commit()
        cursor.execute('SELECT attempts FROM login_attempts WHERE login = ? AND device_id = ?', (login, device_id))
        attempts = cursor.fetchone()[0]
        if attempts >= BLOCK_ATTEMPTS:
            blocked_until = (datetime.datetime.now() + datetime.timedelta(seconds=BLOCK_DURATION)).isoformat()
            cursor.execute(
                'UPDATE login_attempts SET blocked_until = ?, attempts = 0 WHERE login = ? AND device_id = ?',
                (blocked_until, login, device_id))
            conn.commit()
        conn.close()
        return True

    def save_encrypted_master_key(self, login, encrypted_master_key):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET encrypted_master_key = ? WHERE login = ?', (encrypted_master_key, login))
        conn.commit()
        conn.close()
        return True

    def reset_login_attempt(self, login, device_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM login_attempts WHERE login = ? AND device_id = ?', (login, device_id))
        conn.commit()
        conn.close()
        return True

    def is_login_blocked(self, login, device_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT blocked_until FROM login_attempts WHERE login = ? AND device_id = ?', (login, device_id))
        row = cursor.fetchone()
        conn.close()
        if row and row[0]:
            blocked_until = datetime.datetime.fromisoformat(row[0])
            if blocked_until > datetime.datetime.now():
                seconds = (blocked_until - datetime.datetime.now()).seconds
                return True, seconds
        return False, 0

    def get_user_by_session(self, session_id, user_id):
        hashed = hashlib.sha256(SESSION_HASH_SALT + session_id.encode()).hexdigest()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT u.* FROM users u
            JOIN user_sessions s ON u.user_id = s.user_id
            WHERE s.session_id = ? AND u.user_id = ? 
            AND s.is_active = 1 AND s.expires_at > datetime('now')
        ''', (hashed, user_id))
        user = cursor.fetchone()
        conn.close()
        if user:
            return dict(user)
        return None

    def get_user_by_login(self, login):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE login = ?', (login,))
        user = cursor.fetchone()
        conn.close()
        if user:
            return dict(user)
        return None

    def get_user_by_id(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE user_id = ?', (user_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def is_session_active(self, session_id, user_id):
        hashed = hashlib.sha256(SESSION_HASH_SALT + session_id.encode()).hexdigest()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT 1 FROM user_sessions
            WHERE session_id = ? AND user_id = ?
            AND is_active = 1 AND expires_at > datetime('now')
        ''', (hashed, user_id))
        result = cursor.fetchone() is not None
        conn.close()
        return result

    def get_encrypted_master_key(self, login):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT encrypted_master_key FROM users WHERE login = ?', (login,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None

    def create_user_session(self, user_id, user_login, session_id):
        hashed = hashlib.sha256(SESSION_HASH_SALT + session_id.encode()).hexdigest()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM user_sessions WHERE user_id = ? AND is_active = 1', (user_id,))
        if cursor.fetchone()[0] >= 10:
            conn.close()
            return False
        expires_at = datetime.datetime.now() + datetime.timedelta(seconds=TOKEN_LIFETIME)
        cursor.execute('''
            INSERT INTO user_sessions (session_id, user_id, user_login, expires_at)
            VALUES (?, ?, ?, ?)
        ''', (hashed, user_id, user_login, expires_at))
        cursor.execute('SELECT cleanup_interval FROM cleanup_settings WHERE user_id = ?', (user_id,))
        cleanup = cursor.fetchone()
        if cleanup and cleanup[0] == 0:
            cursor.execute('DELETE FROM user_sessions WHERE user_id = ? AND is_active = 0', (user_id,))
        conn.commit()
        conn.close()
        return True

    def deactivate_session(self, session_id, user_id):
        hashed = hashlib.sha256(SESSION_HASH_SALT + session_id.encode()).hexdigest()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE user_sessions SET is_active = 0 WHERE session_id = ? AND user_id = ?
        ''', (hashed, user_id))
        cursor.execute('SELECT cleanup_interval FROM cleanup_settings WHERE user_id = ?', (user_id,))
        cleanup = cursor.fetchone()
        if cleanup and cleanup[0] == 0:
            cursor.execute('DELETE FROM user_sessions WHERE user_id = ? AND is_active = 0', (user_id,))
        conn.commit()
        conn.close()
        return True

    def deactivate_all_sessions_except(self, user_id, except_session_id):
        hashed_except = hashlib.sha256(SESSION_HASH_SALT + except_session_id.encode()).hexdigest()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE user_sessions SET is_active = 0 
            WHERE user_id = ? AND session_id != ? AND expires_at > datetime('now')
        ''', (user_id, hashed_except))
        cursor.execute('SELECT cleanup_interval FROM cleanup_settings WHERE user_id = ?', (user_id,))
        cleanup = cursor.fetchone()
        if cleanup and cleanup[0] == 0:
            cursor.execute('DELETE FROM user_sessions WHERE user_id = ? AND is_active = 0', (user_id,))
        conn.commit()
        conn.close()
        return True

    def deactivate_all_sessions(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE user_sessions SET is_active = 0 WHERE user_id = ?', (user_id,))
        cursor.execute('SELECT cleanup_interval FROM cleanup_settings WHERE user_id = ?', (user_id,))
        cleanup = cursor.fetchone()
        if cleanup and cleanup[0] == 0:
            cursor.execute('DELETE FROM user_sessions WHERE user_id = ? AND is_active = 0', (user_id,))
        conn.commit()
        conn.close()
        return True

    def update_session_last_used(self, session_id):
        hashed = hashlib.sha256(SESSION_HASH_SALT + session_id.encode()).hexdigest()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE user_sessions SET last_used_at = datetime('now') 
            WHERE session_id = ?
        ''', (hashed,))
        conn.commit()
        conn.close()
        return True

    def get_user_sessions(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT session_id, created_at, last_used_at, expires_at, is_active
            FROM user_sessions WHERE user_id = ? ORDER BY last_used_at DESC
        ''', (user_id,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows] if rows else []

    def get_cleanup_interval(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT cleanup_interval FROM cleanup_settings WHERE user_id = ?', (user_id,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else 0

    def set_cleanup_interval(self, user_id, interval):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO cleanup_settings (user_id, cleanup_interval) VALUES (?, ?)
        ''', (user_id, interval))
        if interval == 0:
            cursor.execute('DELETE FROM user_sessions WHERE user_id = ? AND is_active = 0', (user_id,))
        conn.commit()
        conn.close()
        return True

    def get_user_avatar_version(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT avatar_version FROM users WHERE user_id = ?', (user_id,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else 0

    def get_avatar_versions(self, user_ids):
        if not user_ids:
            return {}
        conn = self.get_connection()
        cursor = conn.cursor()
        placeholders = ','.join(['?'] * len(user_ids))
        query = 'SELECT user_id, avatar_version FROM users WHERE user_id IN (' + placeholders + ')'
        cursor.execute(query, user_ids)
        rows = cursor.fetchall()
        conn.close()
        return {row[0]: row[1] for row in rows}

    def get_avatar_data(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT avatar_data FROM user_avatars WHERE user_id = ?', (user_id,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None

    def update_user_avatar(self, user_id, avatar_data):
        compressed = self._compress_avatar(avatar_data)
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET avatar_version = avatar_version + 1 WHERE user_id = ?', (user_id,))
        cursor.execute('''
            INSERT OR REPLACE INTO user_avatars (user_id, avatar_data, file_size)
            VALUES (?, ?, ?)
        ''', (user_id, compressed, len(compressed)))
        conn.commit()
        new_version = cursor.execute('SELECT avatar_version FROM users WHERE user_id = ?', (user_id,)).fetchone()[0]
        conn.close()
        return True, new_version

    def _compress_avatar(self, image_data):
        img = Image.open(io.BytesIO(image_data))
        if img.width > 8000 or img.height > 5000:
            raise ValueError("Image too large")
        if len(image_data) > 150 * 1024:
            raise ValueError("Image too large")
        if img.mode in ('RGBA', 'LA', 'P'):
            img = img.convert('RGB')
        output = io.BytesIO()
        img.save(output, format='JPEG', quality=85, optimize=True, progressive=True)
        compressed = output.getvalue()
        if len(compressed) > 150 * 1024:
            output = io.BytesIO()
            quality = 70
            while len(compressed) > 150 * 1024 and quality >= 30:
                img.save(output, format='JPEG', quality=quality, optimize=True, progressive=True)
                compressed = output.getvalue()
                quality -= 10
        return compressed

    def save_file(self, file_data, file_name, file_type, uploaded_by,
                  is_image_only=False, encrypted_key=None, nonce_file=None,
                  thumbnail_data=None, nonce_thumbnail=None):
        file_size = len(file_data)
        if file_size > 10 * 1024 * 1024:
            return False, "File too large"

        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT COALESCE(SUM(file_size), 0) FROM files WHERE uploaded_by = ?', (uploaded_by,))
        total_size = cursor.fetchone()[0]
        if total_size + file_size > 100 * 1024 * 1024:
            conn.close()
            return False, "Storage limit exceeded"

        is_encrypted = 1 if encrypted_key else 0

        cursor.execute('''
            INSERT INTO files (
                file_name, file_type, file_size, file_data, thumbnail_data,
                uploaded_by, is_image_only, encrypted_key, nonce_file,
                nonce_thumbnail, is_encrypted
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (file_name, file_type, file_size, file_data, thumbnail_data,
              uploaded_by, 1 if is_image_only else 0, encrypted_key,
              nonce_file, nonce_thumbnail, is_encrypted))
        file_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return True, file_id

    def get_file(self, file_id, user_login):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT f.* FROM files f
            WHERE f.id = ? AND (
                f.uploaded_by = ? OR 
                EXISTS (SELECT 1 FROM messages m WHERE m.file_id = ? AND (m.sender_login = ? OR m.receiver_login = ?))
            )
        ''', (file_id, user_login, file_id, user_login, user_login))
        file = cursor.fetchone()
        conn.close()
        if file:
            return dict(file)
        return None

    def send_message(self, sender_login, receiver_login, text, file_id=None, client_timestamp=None, nonce=None):
        conn = self.get_connection()
        cursor = conn.cursor()
        has_file = 1 if file_id else 0
        cursor.execute('''
            INSERT INTO messages (sender_login, receiver_login, message_text, has_file, file_id, client_timestamp, nonce)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (sender_login, receiver_login, text, has_file, file_id, client_timestamp, nonce))
        msg_id = cursor.lastrowid
        cursor.execute('''
            SELECT id, sender_login, receiver_login, message_text, has_file, file_id, timestamp, client_timestamp, nonce
            FROM messages WHERE id = ?
        ''', (msg_id,))
        msg = dict(cursor.fetchone())
        conn.commit()
        conn.close()
        return msg

    def get_messages(self, user_login, other_login):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT m.*, u.username AS sender_name
            FROM messages m
            JOIN users u ON m.sender_login = u.login
            WHERE (m.sender_login = ? AND m.receiver_login = ?)
               OR (m.sender_login = ? AND m.receiver_login = ?)
            ORDER BY m.timestamp ASC
            LIMIT 50
        ''', (user_login, other_login, other_login, user_login))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows] if rows else []

    def get_messages_since(self, user_login, contact_login, since_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT m.*, u.username AS sender_name
            FROM messages m
            JOIN users u ON m.sender_login = u.login
            WHERE ((m.sender_login = ? AND m.receiver_login = ?)
               OR (m.sender_login = ? AND m.receiver_login = ?))
               AND m.id > ?
            ORDER BY m.timestamp ASC
        ''', (user_login, contact_login, contact_login, user_login, since_id))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows] if rows else []

    def add_contact(self, owner_login, contact_login):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO contacts (contact_owner, contact_login) VALUES (?, ?)
        ''', (owner_login, contact_login))
        conn.commit()
        conn.close()
        return True

    def remove_contact(self, owner_login, contact_login):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            DELETE FROM contacts WHERE contact_owner = ? AND contact_login = ?
        ''', (owner_login, contact_login))
        conn.commit()
        conn.close()
        return True

    def get_contacts(self, owner_login):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT u.login, u.username, u.user_id, u.avatar_version
            FROM contacts c
            JOIN users u ON c.contact_login = u.login
            WHERE c.contact_owner = ?
            ORDER BY u.username
        ''', (owner_login,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows] if rows else []

    def is_contact(self, owner_login, contact_login):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM contacts WHERE contact_owner = ? AND contact_login = ?',
                       (owner_login, contact_login))
        result = cursor.fetchone() is not None
        conn.close()
        return result

    def search_users(self, query, current_login):
        conn = self.get_connection()
        cursor = conn.cursor()
        import re
        safe_query = re.escape(query).replace('%', '\\%').replace('_', '\\_')
        pattern = f'%{safe_query}%'
        cursor.execute('''
            SELECT login, username, user_id, avatar_version
            FROM users
            WHERE (login LIKE ? OR username LIKE ?) AND login != ?
            LIMIT 20
        ''', (pattern, pattern, current_login))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows] if rows else []

    def get_contact_settings(self, user_login):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT contact_login, display_name FROM contact_settings WHERE user_login = ?
        ''', (user_login,))
        rows = cursor.fetchall()
        conn.close()
        return {row[0]: {'display_name': row[1]} for row in rows}

    def save_contact_settings(self, user_login, contact_login, display_name):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO contact_settings (user_login, contact_login, display_name)
            VALUES (?, ?, ?)
        ''', (user_login, contact_login, display_name))
        conn.commit()
        conn.close()
        return True

    def save_opaque_password_file(self, login, password_file):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET opaque_password_file = ? WHERE login = ?', (password_file, login))
        conn.commit()
        conn.close()
        return True

    def get_opaque_password_file(self, login):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT opaque_password_file FROM users WHERE login = ?', (login,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None

    def save_login_state(self, login, server_state):
        state_id = str(uuid.uuid4())
        expires_at = datetime.datetime.now() + datetime.timedelta(minutes=5)
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO opaque_login_states (state_id, login, server_state, expires_at)
            VALUES (?, ?, ?, ?)
        ''', (state_id, login, server_state, expires_at))
        conn.commit()
        conn.close()
        return state_id

    def get_login_state(self, state_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT login, server_state, expires_at FROM opaque_login_states WHERE state_id = ?',
                       (state_id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return dict(row)
        return None

    def delete_login_state(self, state_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM opaque_login_states WHERE state_id = ?', (state_id,))
        conn.commit()
        conn.close()
        return True

    def get_user_public_key(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT public_key, signature FROM user_public_keys WHERE user_id = ?', (user_id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return {'public_key': row[0], 'signature': row[1]}
        return None

    def save_user_public_key(self, user_id, public_key, signature):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO user_public_keys (user_id, public_key, signature, updated_at)
            VALUES (?, ?, ?, datetime('now'))
        ''', (user_id, public_key, signature))
        conn.commit()
        conn.close()
        return True

    def add_used_nonce(self, nonce, user_id):
        if len(nonce) > 64:
            return False
        conn = self.get_connection()
        cursor = conn.cursor()
        expires_at = datetime.datetime.now() + datetime.timedelta(seconds=120)
        cursor.execute(
            'INSERT INTO used_nonces (nonce, user_id, expires_at) VALUES (?, ?, ?)',
            (nonce, user_id, expires_at)
        )
        conn.commit()
        conn.close()
        return True

    def is_nonce_used(self, nonce, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM used_nonces WHERE nonce = ? AND user_id = ?', (nonce, user_id))
        result = cursor.fetchone() is not None
        conn.close()
        return result

    def update_user_status(self, user_id, status, device_id=None):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO user_status (user_id, status, last_seen, current_device_id)
            VALUES (?, ?, CURRENT_TIMESTAMP, ?)
        ''', (user_id, status, device_id))
        conn.commit()
        conn.close()

    def get_user_status(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT status, last_seen FROM user_status WHERE user_id = ?
        ''', (user_id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return {'status': row[0], 'last_seen': row[1]}
        return {'status': 'offline', 'last_seen': None}

    def register_connection(self, session_id, user_id, device_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO active_connections (session_id, user_id, device_id, last_ping)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ''', (session_id, user_id, device_id))
        conn.commit()
        conn.close()

    def update_connection_ping(self, session_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE active_connections SET last_ping = CURRENT_TIMESTAMP
            WHERE session_id = ?
        ''', (session_id,))
        conn.commit()
        conn.close()


db = Database()


def login_required(f):
    def decorated(*args, **kwargs):
        session_id = request.headers.get('X-Session-Id')
        user_id_str = request.headers.get('X-User-Id')
        if not session_id or not user_id_str:
            return jsonify({'success': False, 'error': 'Missing credentials'}), 401
        user_id = int(user_id_str)

        user = db.get_user_by_session(session_id, user_id)
        if not user:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        db.update_session_last_used(session_id)
        db.update_connection_ping(session_id)
        data = request.get_json(silent=True) or {}
        return f(user, data, *args, **kwargs)

    decorated.__name__ = f.__name__
    return decorated


event_queues = {}
event_queues_lock = threading.Lock()


def add_event(user_id, event_type, data):
    with event_queues_lock:
        if user_id not in event_queues:
            event_queues[user_id] = queue.Queue()
        event_queues[user_id].put((event_type, data))


def get_event_queue(user_id):
    with event_queues_lock:
        return event_queues.get(user_id)


def remove_event_queue(user_id):
    with event_queues_lock:
        if user_id in event_queues:
            del event_queues[user_id]


@app.route('/api/opaque/register/start', methods=['POST'])
@rate_limit
def opaque_register_start():
    data = request.get_json()
    login = data.get('login')
    username = data.get('username')
    if not login or not username:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    if db.get_user_by_login(login):
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    conn = db.get_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE username = ?', (username,))
    exists = cur.fetchone()
    conn.close()
    if exists:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    return jsonify({'success': True})


@app.route('/api/opaque/register/finish', methods=['POST'])
@rate_limit
def opaque_register_finish():
    data = request.get_json()
    login = data.get('login')
    username = data.get('username')
    registration_request = base64.b64decode(data.get('registration_request'))
    if not login or not username or not registration_request:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    if db.get_user_by_login(login):
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    server_setup = opaque_ke_py.ServerSetupData.from_bytes(SERVER_SETUP_BYTES)
    server_reg_start = opaque_ke_py.server_registration_start(
        server_setup,
        registration_request,
        login.encode('utf-8')
    )
    server_response = server_reg_start.get_message()
    return jsonify({
        'success': True,
        'server_response': base64.b64encode(server_response).decode('utf-8')
    })


@app.route('/api/opaque/register/upload', methods=['POST'])
@rate_limit
def opaque_register_upload():
    data = request.get_json()
    login = data.get('login')
    username = data.get('username')
    registration_upload = base64.b64decode(data.get('registration_upload'))
    encrypted_master_key = data.get('encrypted_master_key')
    if not login or not username or not registration_upload or not encrypted_master_key:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    if db.get_user_by_login(login):
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    server_setup = opaque_ke_py.ServerSetupData.from_bytes(SERVER_SETUP_BYTES)
    server_reg_finish = opaque_ke_py.server_registration_finish(registration_upload)
    password_file = server_reg_finish.get_password_file()
    conn = db.get_connection()
    cur = conn.cursor()
    cur.execute('SELECT COALESCE(MAX(user_id), 1000) + 1 FROM users')
    user_id = cur.fetchone()[0]
    cur.execute('''
        INSERT INTO users (login, username, user_id, opaque_password_file, encrypted_master_key)
        VALUES (?, ?, ?, ?, ?)
    ''', (login, username, user_id, password_file, encrypted_master_key))
    conn.commit()
    db.set_cleanup_interval(user_id, 0)
    conn.close()
    return jsonify({
        'success': True,
        'user_id': user_id
    })


@app.route('/api/opaque/login/start', methods=['POST'])
@rate_limit
def opaque_login_start():
    data = request.get_json()
    login = data.get('login')
    credential_request = base64.b64decode(data.get('credential_request'))
    device_id = request.headers.get('X-Device-ID')
    if not login or not credential_request:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    if not device_id:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400

    blocked, seconds = db.is_login_blocked(login, device_id)
    if blocked:
        return jsonify({'success': False, 'error': 'Too many attempts'}), 429

    user = db.get_user_by_login(login)
    if not user:
        db.increment_login_attempt(login, device_id)
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

    password_file = db.get_opaque_password_file(login)
    if not password_file:
        db.increment_login_attempt(login, device_id)
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

    server_setup = opaque_ke_py.ServerSetupData.from_bytes(SERVER_SETUP_BYTES)
    server_login_start = opaque_ke_py.server_login_start(
        server_setup,
        password_file,
        credential_request,
        login.encode('utf-8')
    )

    credential_response = server_login_start.get_message()
    server_state = server_login_start.get_state()
    state_id = db.save_login_state(login, server_state)

    return jsonify({
        'success': True,
        'state_id': state_id,
        'credential_response': base64.b64encode(credential_response).decode('utf-8')
    })


@app.route('/api/opaque/login/finish', methods=['POST'])
@rate_limit
def opaque_login_finish():
    data = request.get_json()
    state_id = data.get('state_id')
    credential_finalization = base64.b64decode(data.get('credential_finalization'))
    device_id = request.headers.get('X-Device-ID')
    if not state_id or not credential_finalization:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    if not device_id:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400

    state = db.get_login_state(state_id)
    if not state:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    expires_at = datetime.datetime.fromisoformat(state['expires_at'])
    if expires_at < datetime.datetime.now():
        db.delete_login_state(state_id)
        return jsonify({'success': False, 'error': 'Invalid data'}), 400

    login = state['login']
    server_state = state['server_state']

    server_setup = opaque_ke_py.ServerSetupData.from_bytes(SERVER_SETUP_BYTES)
    server_login_finish = opaque_ke_py.server_login_finish(server_state, credential_finalization)
    db.delete_login_state(state_id)

    user = db.get_user_by_login(login)
    if not user:
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

    db.reset_login_attempt(login, device_id)

    session_id = str(uuid.uuid4())
    if not db.create_user_session(user['user_id'], user['login'], session_id):
        return jsonify({'success': False, 'error': 'Too many active sessions'}), 429

    encrypted_master_key = db.get_encrypted_master_key(user['login'])

    db.register_connection(session_id, user['user_id'], device_id)
    db.update_user_status(user['user_id'], 'online', device_id)

    return jsonify({
        'success': True,
        'session_id': session_id,
        'user_id': user['user_id'],
        'username': user['username'],
        'encrypted_master_key': encrypted_master_key,
        'e2ee_salt': user.get('e2ee_salt')
    })


@app.route('/api/opaque/login/failed', methods=['POST'])
@rate_limit
def opaque_login_failed():
    data = request.get_json()
    login = data.get('login')
    device_id = request.headers.get('X-Device-ID')

    if not login or not device_id:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400

    db.increment_login_attempt(login, device_id)
    blocked, seconds = db.is_login_blocked(login, device_id)
    if blocked:
        return jsonify({
            'success': False,
            'error': 'Too many attempts',
            'blocked': True,
            'seconds': seconds
        }), 429

    return jsonify({'success': True})


@app.route('/api/opaque/change_password/get_server_response', methods=['POST'])
@rate_limit
@login_required
def opaque_change_password_get_server_response(user, data):
    registration_request = base64.b64decode(data.get('registration_request'))
    if not registration_request:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    server_setup = opaque_ke_py.ServerSetupData.from_bytes(SERVER_SETUP_BYTES)
    server_reg_start = opaque_ke_py.server_registration_start(
        server_setup,
        registration_request,
        user['login'].encode('utf-8')
    )
    server_response = server_reg_start.get_message()
    return jsonify({
        'success': True,
        'server_response': base64.b64encode(server_response).decode('utf-8')
    })


@app.route('/api/opaque/change_password/upload', methods=['POST'])
@rate_limit
@login_required
def opaque_change_password_upload(user, data):
    registration_upload = base64.b64decode(data.get('registration_upload'))
    encrypted_master_key = data.get('encrypted_master_key')
    if not registration_upload:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    server_reg_finish = opaque_ke_py.server_registration_finish(registration_upload)
    new_password_file = server_reg_finish.get_password_file()
    db.save_opaque_password_file(user['login'], new_password_file)
    if encrypted_master_key:
        db.save_encrypted_master_key(user['login'], encrypted_master_key)

    current_session = request.headers.get('X-Session-Id')
    if current_session:
        db.deactivate_all_sessions_except(user['user_id'], current_session)
    else:
        db.deactivate_all_sessions(user['user_id'])

    return jsonify({'success': True})


@app.route('/api/auth', methods=['POST'])
@rate_limit
@login_required
def auth(user, data):
    return jsonify({'success': True})


@app.route('/api/logout_current', methods=['POST'])
@rate_limit
@login_required
def logout_current(user, data):
    session_id = request.headers.get('X-Session-Id')
    if session_id:
        db.deactivate_session(session_id, user['user_id'])
        db.update_user_status(user['user_id'], 'offline')
    remove_event_queue(user['user_id'])
    return jsonify({'success': True})


@app.route('/api/info', methods=['GET', 'POST'])
@rate_limit
@login_required
def info(user, data):
    if request.method == 'GET':
        include_avatar = request.args.get('include_avatar', 'false').lower() == 'true'
    else:
        include_avatar = data.get('include_avatar', False)
    avatar_version = db.get_user_avatar_version(user['user_id'])
    response = {
        'success': True,
        'user_id': user['user_id'],
        'username': user['username'],
        'avatar_version': avatar_version
    }
    if include_avatar:
        avatar_data = db.get_avatar_data(user['user_id'])
        if avatar_data:
            response['avatar'] = base64.b64encode(avatar_data).decode('utf-8')
    return jsonify(response)


@app.route('/api/update_status', methods=['POST'])
@rate_limit
@login_required
def update_status(user, data):
    status = data.get('status', 'online')
    device_id = request.headers.get('X-Device-ID')
    session_id = request.headers.get('X-Session-Id')

    db.update_user_status(user['user_id'], status, device_id)
    db.register_connection(session_id, user['user_id'], device_id)

    contacts = db.get_contacts(user['login'])
    for contact in contacts:
        add_event(contact['user_id'], 'status_changed', {
            'user_id': user['user_id'],
            'status': status,
            'last_seen': datetime.datetime.now().isoformat()
        })

    return jsonify({'success': True})


@app.route('/api/get_status', methods=['POST'])
@rate_limit
@login_required
def get_status(user, data):
    target_user_id = data.get('target_user_id')
    if not target_user_id:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400

    status = db.get_user_status(target_user_id)
    return jsonify({'success': True, 'status': status})


@app.route('/api/ping', methods=['POST'])
@rate_limit
@login_required
def ping(user, data):
    session_id = request.headers.get('X-Session-Id')
    db.update_connection_ping(session_id)
    db.update_user_status(user['user_id'], 'online')
    return jsonify({'success': True})


@app.route('/api/get_sessions', methods=['POST'])
@rate_limit
@login_required
def get_sessions(user, data):
    sessions = db.get_user_sessions(user['user_id'])
    current_session = request.headers.get('X-Session-Id')
    current_hashed = hashlib.sha256(
        SESSION_HASH_SALT + current_session.encode()).hexdigest() if current_session else None
    formatted = []
    for s in sessions:
        expires_at = datetime.datetime.fromisoformat(s['expires_at'])
        expires_in = max(0, (expires_at - datetime.datetime.now()).total_seconds())
        display_id = s['session_id'][:8] + '...'
        formatted.append({
            'session_id': display_id,
            'full_hash': s['session_id'],
            'created_at': s['created_at'],
            'last_used_at': s['last_used_at'],
            'expires_at': s['expires_at'],
            'expires_in': int(expires_in),
            'is_active': bool(s['is_active']),
            'is_current': s['session_id'] == current_hashed
        })
    return jsonify({'success': True, 'sessions': formatted})


@app.route('/api/logout_session', methods=['POST'])
@rate_limit
@login_required
def logout_session(user, data):
    target_hash = data.get('target_session_hash')
    if not target_hash:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE user_sessions SET is_active = 0 
        WHERE session_id = ? AND user_id = ?
    ''', (target_hash, user['user_id']))
    cursor.execute('SELECT cleanup_interval FROM cleanup_settings WHERE user_id = ?', (user['user_id'],))
    cleanup = cursor.fetchone()
    if cleanup and cleanup[0] == 0:
        cursor.execute('DELETE FROM user_sessions WHERE user_id = ? AND is_active = 0', (user['user_id'],))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/logout_all_sessions', methods=['POST'])
@rate_limit
@login_required
def logout_all_sessions(user, data):
    current = request.headers.get('X-Session-Id')
    if current:
        db.deactivate_all_sessions_except(user['user_id'], current)
    else:
        db.deactivate_all_sessions(user['user_id'])
    return jsonify({'success': True})


@app.route('/api/get_cleanup_interval', methods=['POST'])
@rate_limit
@login_required
def get_cleanup_interval(user, data):
    interval = db.get_cleanup_interval(user['user_id'])
    return jsonify({'success': True, 'cleanup_interval': interval})


@app.route('/api/set_cleanup_interval', methods=['POST'])
@rate_limit
@login_required
def set_cleanup_interval(user, data):
    interval = data.get('interval')
    if interval is None or interval < 0:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    db.set_cleanup_interval(user['user_id'], interval)
    return jsonify({'success': True})


@app.route('/api/search_users', methods=['POST'])
@rate_limit
@login_required
def search_users(user, data):
    query = data.get('search_query', '').strip()
    if not query:
        return jsonify({'success': True, 'users': []})
    users = db.search_users(query, user['login'])
    return jsonify({'success': True, 'users': users})


@app.route('/api/get_user_info', methods=['POST'])
@rate_limit
@login_required
def get_user_info(user, data):
    target = data.get('target_login')
    if not target:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    target_user = db.get_user_by_login(target)
    if not target_user:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    is_contact = db.is_contact(user['login'], target)
    return jsonify({
        'success': True,
        'user': {
            'login': target_user['login'],
            'username': target_user['username'],
            'user_id': target_user['user_id'],
            'avatar_version': target_user['avatar_version'],
            'is_contact': is_contact
        }
    })


@app.route('/api/upload_file', methods=['POST'])
@rate_limit
@login_required
def upload_file(user, data):
    file_data = data.get('file_data')
    file_name = data.get('file_name')
    file_type = data.get('file_type')
    is_image_only = data.get('is_image_only', False)
    encrypted_key = data.get('encrypted_key')
    nonce_file = data.get('nonce_file')
    thumbnail = data.get('thumbnail')
    nonce_thumbnail = data.get('nonce_thumbnail')

    if not file_data or not file_name or not file_type:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400

    file_bytes = base64.b64decode(file_data)
    thumb_bytes = base64.b64decode(thumbnail) if thumbnail else None
    success, result = db.save_file(
        file_bytes, file_name, file_type, user['login'],
        is_image_only=is_image_only,
        encrypted_key=encrypted_key,
        nonce_file=nonce_file,
        thumbnail_data=thumb_bytes,
        nonce_thumbnail=nonce_thumbnail
    )
    if success:
        return jsonify({'success': True, 'file_id': result})
    else:
        return jsonify({'success': False, 'error': result}), 400


@app.route('/api/get_file', methods=['POST'])
@rate_limit
@login_required
def get_file(user, data):
    file_id = data.get('file_id')
    include_data = data.get('include_data', True)
    include_thumbnail = data.get('include_thumbnail', False)
    if not file_id:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400

    file = db.get_file(file_id, user['login'])
    if not file:
        return jsonify({'success': False, 'error': 'File not found'}), 404

    response = {
        'success': True,
        'file_id': file['id'],
        'file_name': file['file_name'],
        'file_type': file['file_type'],
        'file_size': file['file_size'],
        'is_image_only': bool(file['is_image_only']),
        'is_encrypted': bool(file['is_encrypted']),
        'encrypted_key': file['encrypted_key'],
        'nonce_file': file['nonce_file'],
        'nonce_thumbnail': file['nonce_thumbnail']
    }

    if include_data and file['file_data']:
        response['file_data'] = base64.b64encode(file['file_data']).decode('utf-8')
    if include_thumbnail and file.get('thumbnail_data'):
        response['thumbnail'] = base64.b64encode(file['thumbnail_data']).decode('utf-8')

    return jsonify(response)


@app.route('/api/send_message', methods=['POST'])
@rate_limit
@login_required
def send_message(user, data):
    receiver = data.get('receiver_login')
    text = data.get('text', '')
    file_id = data.get('file_id')
    client_timestamp = data.get('client_timestamp')
    nonce = data.get('nonce')

    if not receiver:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    if not text and not file_id:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400

    receiver_user = db.get_user_by_login(receiver)
    if not receiver_user:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400

    if nonce:
        if db.is_nonce_used(nonce, user['user_id']):
            return jsonify({'success': False, 'error': 'Nonce already used'}), 400
        db.add_used_nonce(nonce, user['user_id'])

    msg = db.send_message(user['login'], receiver, text, file_id, client_timestamp, nonce)
    file_info = None
    if file_id:
        file = db.get_file(file_id, user['login'])
        if file:
            file_info = {
                'id': file['id'],
                'name': file['file_name'],
                'type': file['file_type'],
                'size': file['file_size'],
                'is_image_only': bool(file['is_image_only']),
                'is_encrypted': bool(file['is_encrypted']),
                'encrypted_key': file['encrypted_key'],
                'nonce_file': file['nonce_file'],
                'nonce_thumbnail': file['nonce_thumbnail']
            }
    msg_with_file = dict(msg)
    msg_with_file['file_info'] = file_info
    add_event(receiver_user['user_id'], 'new_message', msg_with_file)
    return jsonify({'success': True, 'message': msg_with_file})


@app.route('/api/get_messages', methods=['POST'])
@rate_limit
@login_required
def get_messages(user, data):
    other = data.get('other_user_login')
    if not other:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    messages = db.get_messages(user['login'], other)
    for msg in messages:
        if msg['has_file'] and msg['file_id']:
            file = db.get_file(msg['file_id'], user['login'])
            if file:
                msg['file_info'] = {
                    'id': file['id'],
                    'name': file['file_name'],
                    'type': file['file_type'],
                    'size': file['file_size'],
                    'is_image_only': bool(file['is_image_only']),
                    'is_encrypted': bool(file['is_encrypted']),
                    'encrypted_key': file['encrypted_key'],
                    'nonce_file': file['nonce_file'],
                    'nonce_thumbnail': file['nonce_thumbnail']
                }
    return jsonify({'success': True, 'messages': messages})


@app.route('/api/get_messages_since', methods=['POST'])
@rate_limit
@login_required
def get_messages_since(user, data):
    contact_login = data.get('contact_login')
    since_id = data.get('since_id', 0)
    if not contact_login:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    messages = db.get_messages_since(user['login'], contact_login, since_id)
    for msg in messages:
        if msg['has_file'] and msg['file_id']:
            file = db.get_file(msg['file_id'], user['login'])
            if file:
                msg['file_info'] = {
                    'id': file['id'],
                    'name': file['file_name'],
                    'type': file['file_type'],
                    'size': file['file_size'],
                    'is_image_only': bool(file['is_image_only']),
                    'is_encrypted': bool(file['is_encrypted']),
                    'encrypted_key': file['encrypted_key'],
                    'nonce_file': file['nonce_file'],
                    'nonce_thumbnail': file['nonce_thumbnail']
                }
    return jsonify({'success': True, 'messages': messages})


@app.route('/api/update_profile', methods=['POST'])
@rate_limit
@login_required
def update_profile(user, data):
    username = data.get('username')
    avatar = data.get('avatar')
    if username:
        conn = db.get_connection()
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE username = ? AND login != ?', (username, user['login']))
        if cur.fetchone():
            conn.close()
            return jsonify({'success': False, 'error': 'Invalid data'}), 400
        conn.close()
        conn = db.get_connection()
        cur = conn.cursor()
        cur.execute('UPDATE users SET username = ? WHERE login = ?', (username, user['login']))
        conn.commit()
        conn.close()
    if avatar:
        avatar_bytes = base64.b64decode(avatar)
        success, res = db.update_user_avatar(user['user_id'], avatar_bytes)
        if not success:
            return jsonify({'success': False, 'error': 'Invalid data'}), 400
        avatar_version = res
        conn = db.get_connection()
        cur = conn.cursor()
        cur.execute('SELECT contact_owner FROM contacts WHERE contact_login = ?', (user['login'],))
        owners = cur.fetchall()
        conn.close()
        for owner in owners:
            owner_user = db.get_user_by_login(owner[0])
            if owner_user:
                add_event(owner_user['user_id'], 'avatar_updated', {
                    'user_id': user['user_id'],
                    'new_version': avatar_version
                })
        avatar_data = db.get_avatar_data(user['user_id'])
        if avatar_data:
            return jsonify({
                'success': True,
                'avatar_version': avatar_version,
                'avatar': base64.b64encode(avatar_data).decode('utf-8')
            })
        else:
            return jsonify({'success': True, 'avatar_version': avatar_version})
    return jsonify({'success': True})


@app.route('/api/add_contact', methods=['POST'])
@rate_limit
@login_required
def add_contact(user, data):
    contact = data.get('contact_login')
    if not contact:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    if contact == user['login']:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    target = db.get_user_by_login(contact)
    if not target:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    if db.add_contact(user['login'], contact):
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400


@app.route('/api/remove_contact', methods=['POST'])
@rate_limit
@login_required
def remove_contact(user, data):
    contact = data.get('contact_login')
    if not contact:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    db.remove_contact(user['login'], contact)
    return jsonify({'success': True})


@app.route('/api/get_contacts', methods=['POST'])
@rate_limit
@login_required
def get_contacts(user, data):
    contacts = db.get_contacts(user['login'])
    return jsonify({'success': True, 'contacts': contacts})


@app.route('/api/get_avatar_versions', methods=['POST'])
@rate_limit
@login_required
def get_avatar_versions(user, data):
    user_ids = data.get('user_ids', [])
    versions = db.get_avatar_versions(user_ids)
    return jsonify({'success': True, 'versions': versions})


@app.route('/api/get_avatar', methods=['POST'])
@rate_limit
@login_required
def get_avatar(user, data):
    target_id = data.get('target_user_id')
    if not target_id:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    avatar_data = db.get_avatar_data(target_id)
    if avatar_data:
        return jsonify({
            'success': True,
            'avatar': base64.b64encode(avatar_data).decode('utf-8')
        })
    else:
        return jsonify({'success': False, 'error': 'Invalid data'}), 404


@app.route('/api/save_contact_settings', methods=['POST'])
@rate_limit
@login_required
def save_contact_settings(user, data):
    contact = data.get('contact_login')
    display_name = data.get('display_name')
    if not contact:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    db.save_contact_settings(user['login'], contact, display_name)
    return jsonify({'success': True})


@app.route('/api/get_contact_settings', methods=['POST'])
@rate_limit
@login_required
def get_contact_settings(user, data):
    settings = db.get_contact_settings(user['login'])
    return jsonify({'success': True, 'settings': settings})


@app.route('/api/publish_public_key', methods=['POST'])
@rate_limit
@login_required
def publish_public_key(user, data):
    public_key = data.get('public_key')
    signature = data.get('signature')
    if not public_key or not signature:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    db.save_user_public_key(user['user_id'], public_key, signature)
    return jsonify({'success': True})


@app.route('/api/get_public_key', methods=['POST'])
@rate_limit
@login_required
def get_public_key(user, data):
    contact_login = data.get('contact_login')
    if not contact_login:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    contact = db.get_user_by_login(contact_login)
    if not contact:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    key_data = db.get_user_public_key(contact['user_id'])
    if key_data:
        return jsonify({'success': True, 'public_key': key_data['public_key'], 'signature': key_data['signature']})
    else:
        return jsonify({'success': False, 'error': 'Invalid data'}), 404


@app.route('/api/events')
@rate_limit
def events():
    session_id = request.headers.get('X-Session-Id')
    user_id_str = request.headers.get('X-User-Id')
    device_id = request.headers.get('X-Device-ID')

    if not device_id:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    if not session_id or not user_id_str:
        return jsonify({'success': False, 'error': 'Invalid data'}), 401
    user_id = int(user_id_str)

    user = db.get_user_by_session(session_id, user_id)
    if not user:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401

    db.update_session_last_used(session_id)
    db.update_connection_ping(session_id)

    q = get_event_queue(user_id)
    if q is None:
        with event_queues_lock:
            if user_id not in event_queues:
                event_queues[user_id] = queue.Queue()
            q = event_queues[user_id]

    def generate():
        import queue as _queue
        while True:
            try:
                event_type, event_data = q.get(timeout=30)
                yield f"event: {event_type}\ndata: {json.dumps(event_data, ensure_ascii=False)}\n\n"
            except _queue.Empty:
                yield ": keepalive\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )


@app.route('/', methods=['GET'])
def health():
    return 'Healthy.'


if __name__ == '__main__':
    app.run(host=SERVER_HOST, port=SERVER_PORT, threaded=True)