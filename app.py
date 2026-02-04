import socket
import threading
import json
import sqlite3
import uuid
import datetime
import os
import hashlib
import base64
import hmac
from pathlib import Path
import secrets
from threading import Timer

SERVER_HOST = 'localhost'
SERVER_PORT = 5000
MAX_CONNECTIONS = 10000
BUFFER_SIZE = 4096
active_connections = {}

AVATARS_DIR = Path('avatars')
AVATARS_DIR.mkdir(exist_ok=True)

CLEANUP_INTERVAL = 86400

session_cleanup_timer = None

SECRET_KEY = secrets.token_hex(32).encode()


def start_session_cleanup_timer(interval=CLEANUP_INTERVAL):
    global session_cleanup_timer
    if session_cleanup_timer:
        session_cleanup_timer.cancel()

    def cleanup_job():
        cleanup_expired_sessions()
        start_session_cleanup_timer(interval)

    session_cleanup_timer = Timer(interval, cleanup_job)
    session_cleanup_timer.daemon = True
    session_cleanup_timer.start()


def cleanup_expired_sessions():
    conn = sqlite3.connect('messenger.db', check_same_thread=False)
    cursor = conn.cursor()

    cursor.execute('''
        select distinct user_id from cleanup_settings where cleanup_interval = 0
    ''')
    users_immediate = [row[0] for row in cursor.fetchall()]

    for user_id in users_immediate:
        cursor.execute('''
            delete from user_sessions 
            where user_id = ? and is_active = 0
        ''', (user_id,))

    cursor.execute('''
        select distinct user_id, cleanup_interval from cleanup_settings where cleanup_interval > 0
    ''')
    users_with_interval = cursor.fetchall()

    for user_id, interval in users_with_interval:
        cutoff_time = datetime.datetime.now() - datetime.timedelta(seconds=interval)
        cursor.execute('''
            delete from user_sessions 
            where user_id = ? and is_active = 0 and last_used_at < ?
        ''', (user_id, cutoff_time))

    conn.commit()
    conn.close()


def verify_password(password, stored_hash):
    if not stored_hash:
        return False

    if ':' in stored_hash:
        stored_hash_parts = stored_hash.split(':')
        if len(stored_hash_parts) != 2:
            return False

        stored_password_hash, salt = stored_hash_parts
        new_hash = hashlib.sha256((password + salt).encode()).hexdigest()

        return new_hash == stored_password_hash
    else:
        old_hash = hashlib.sha256(password.encode()).hexdigest()
        return old_hash == stored_hash


def migrate_password_in_database(db, login, password):
    conn = db.get_connection()
    cursor = conn.cursor()

    salt = base64.b64encode(os.urandom(16)).decode('utf-8')[:16]
    new_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    stored_password = f"{new_hash}:{salt}"

    cursor.execute(
        'update users set password = ? where login = ?',
        (stored_password, login)
    )
    conn.commit()
    conn.close()

    return stored_password


def create_session_token(session_id, user_id):
    data = f"{session_id}:{user_id}"
    signature = hmac.new(
        SECRET_KEY,
        data.encode(),
        hashlib.sha256
    ).hexdigest()
    token_data = f"{session_id}:{signature}"
    return base64.b64encode(token_data.encode()).decode()


def verify_session_token(session_token, user_id):
    try:
        token_data = base64.b64decode(session_token.encode()).decode()
        parts = token_data.split(":")
        if len(parts) != 2:
            return None

        session_id, signature = parts

        expected_data = f"{session_id}:{user_id}"
        expected_signature = hmac.new(
            SECRET_KEY,
            expected_data.encode(),
            hashlib.sha256
        ).hexdigest()

        if signature != expected_signature:
            return None

        return session_id
    except:
        return None


class Database:
    def __init__(self, db_path='messenger.db'):
        self.db_path = db_path
        self.init_db()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            create table if not exists users (
                login text primary key,
                password text not null,
                username text not null unique,
                avatar text,
                user_token text unique,
                user_id integer unique
            )
        ''')
        cursor.execute('''
            create table if not exists messages (
                id integer primary key autoincrement,
                sender_login text not null,
                receiver_login text not null,
                message_text text not null,
                timestamp datetime default current_timestamp,
                foreign key (sender_login) references users (login),
                foreign key (receiver_login) references users (login)
            )
        ''')
        cursor.execute('''
            create table if not exists contacts (
                id integer primary key autoincrement,
                contact_owner text not null,
                contact_login text not null,
                foreign key (contact_owner) references users(login),
                foreign key (contact_login) references users(login),
                unique(contact_owner, contact_login)
            )
        ''')
        cursor.execute('''
            create table if not exists contact_settings (
                id integer primary key autoincrement,
                user_login text not null,
                contact_login text not null,
                display_name text,
                foreign key (user_login) references users(login),
                foreign key (contact_login) references users(login),
                unique(user_login, contact_login)
            )
        ''')
        cursor.execute('''
            create table if not exists user_sessions (
                session_id text primary key,
                user_id integer not null,
                user_login text not null,
                created_at datetime default current_timestamp,
                last_used_at datetime default current_timestamp,
                is_active integer default 1,
                foreign key (user_id) references users(user_id),
                foreign key (user_login) references users(login)
            )
        ''')
        cursor.execute('''
            create table if not exists cleanup_settings (
                user_id integer primary key,
                cleanup_interval integer default 0,
                foreign key (user_id) references users(user_id)
            )
        ''')
        conn.commit()
        conn.close()

    def get_user_by_token(self, user_token, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            select u.* from users u
            join user_sessions s on u.user_id = s.user_id
            where s.session_id = ? and u.user_id = ? and s.is_active = 1
        ''', (user_token, user_id))

        user = cursor.fetchone()
        conn.close()
        if user:
            return dict(user)
        return None

    def get_user_by_session_token(self, session_token, user_id):
        session_id = verify_session_token(session_token, user_id)
        if not session_id:
            return None

        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            select u.* from users u
            join user_sessions s on u.user_id = s.user_id
            where s.session_id = ? and u.user_id = ? and s.is_active = 1
        ''', (session_id, user_id))

        user = cursor.fetchone()
        conn.close()
        if user:
            return dict(user)
        return None

    def get_user_sessions(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            select session_id, created_at, last_used_at, is_active
            from user_sessions
            where user_id = ?
            order by last_used_at desc
        ''', (user_id,))
        sessions = cursor.fetchall()
        conn.close()
        if sessions:
            return [dict(session) for session in sessions]
        return []

    def create_user_session(self, user_id, user_login, session_id):
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            insert into user_sessions (session_id, user_id, user_login)
            values (?, ?, ?)
        ''', (session_id, user_id, user_login))

        cursor.execute('''
            select cleanup_interval from cleanup_settings where user_id = ?
        ''', (user_id,))
        cleanup_result = cursor.fetchone()

        if cleanup_result and cleanup_result[0] == 0:
            cursor.execute('''
                delete from user_sessions 
                where user_id = ? and is_active = 0
            ''', (user_id,))

        conn.commit()
        conn.close()
        return True

    def update_session_last_used(self, session_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            update user_sessions
            set last_used_at = datetime('now')
            where session_id = ?
        ''', (session_id,))
        conn.commit()
        conn.close()
        return True

    def deactivate_session(self, session_id, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            update user_sessions
            set is_active = 0
            where session_id = ? and user_id = ?
        ''', (session_id, user_id))

        cursor.execute('''
            select cleanup_interval from cleanup_settings where user_id = ?
        ''', (user_id,))
        cleanup_result = cursor.fetchone()

        if cleanup_result and cleanup_result[0] == 0:
            cursor.execute('''
                delete from user_sessions 
                where user_id = ? and is_active = 0
            ''', (user_id,))

        conn.commit()
        conn.close()
        return True

    def deactivate_all_sessions_except(self, user_id, except_session_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            update user_sessions
            set is_active = 0
            where user_id = ? and session_id != ?
        ''', (user_id, except_session_id))

        cursor.execute('''
            select cleanup_interval from cleanup_settings where user_id = ?
        ''', (user_id,))
        cleanup_result = cursor.fetchone()

        if cleanup_result and cleanup_result[0] == 0:
            cursor.execute('''
                delete from user_sessions 
                where user_id = ? and is_active = 0
            ''', (user_id,))

        conn.commit()
        conn.close()
        return True

    def deactivate_all_sessions(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            update user_sessions
            set is_active = 0
            where user_id = ?
        ''', (user_id,))

        cursor.execute('''
            select cleanup_interval from cleanup_settings where user_id = ?
        ''', (user_id,))
        cleanup_result = cursor.fetchone()

        if cleanup_result and cleanup_result[0] == 0:
            cursor.execute('''
                delete from user_sessions 
                where user_id = ? and is_active = 0
            ''', (user_id,))

        conn.commit()
        conn.close()
        return True

    def get_cleanup_interval(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            select cleanup_interval from cleanup_settings where user_id = ?
        ''', (user_id,))
        result = cursor.fetchone()
        conn.close()
        if result:
            return result[0]
        return 0

    def set_cleanup_interval(self, user_id, interval):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            insert or replace into cleanup_settings (user_id, cleanup_interval)
            values (?, ?)
        ''', (user_id, interval))

        if interval == 0:
            cursor.execute('''
                delete from user_sessions 
                where user_id = ? and is_active = 0
            ''', (user_id,))
            print(f"[*] Немедленная очистка завершенных сессий для пользователя {user_id}")

        conn.commit()
        conn.close()
        return True

    def execute_query(self, query, params=()):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)
        result = cursor.fetchall()
        conn.commit()
        conn.close()
        if result:
            return [dict(row) for row in result]
        return None

    def execute_update(self, query, params=()):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
        conn.close()
        return True


class RequestHandler:
    def __init__(self):
        self.db = Database()

    def handle_request(self, request_data):
        request = json.loads(request_data.decode('utf-8'))
        endpoint = request.get('endpoint')
        data = request.get('data', {})

        if not endpoint:
            return {'success': False, 'error': 'Endpoint not specified'}

        method_name = f'handle_{endpoint}'
        if hasattr(self, method_name):
            result = getattr(self, method_name)(data)
            return result
        else:
            return {'success': False, 'error': f'Unknown endpoint: {endpoint}'}

    def handle_register(self, data):
        login = data.get('login')
        password = data.get('password')
        username = data.get('username')

        if not login or not password or not username:
            return {'success': False, 'error': 'Все поля обязательны для заполнения'}

        result = self.db.execute_query('select * from users where login = ?', (login,))
        if result:
            return {'success': False, 'error': 'Логин уже занят'}

        result = self.db.execute_query('select * from users where username = ?', (username,))
        if result:
            return {'success': False, 'error': 'Имя пользователя уже занято'}

        user_token = str(uuid.uuid4())
        user_id = int(datetime.datetime.now().timestamp() * 1000000) % 1000000000

        query = '''
            insert into users (login, password, username, user_token, user_id)
            values (?, ?, ?, ?, ?)
        '''

        if self.db.execute_update(query, (login, password, username, user_token, user_id)):
            self.db.set_cleanup_interval(user_id, 0)
            return {
                'success': True,
                'user_token': user_token,
                'user_id': user_id
            }
        else:
            return {'success': False, 'error': 'Ошибка при регистрации пользователя'}

    def handle_login(self, data):
        login = data.get('login')
        password = data.get('password')

        result = self.db.execute_query('select * from users where login = ?', (login,))
        if not result:
            return {'success': False, 'error': 'Неверный логин или пароль'}

        user = result[0]
        stored_password = user['password']

        if verify_password(password, stored_password):
            if ':' not in stored_password:
                new_password_hash = migrate_password_in_database(self.db, login, password)
                print(f"Пароль пользователя {login} мигрирован к новому формату")

            session_id = str(uuid.uuid4())
            session_token = create_session_token(session_id, user['user_id'])

            self.db.create_user_session(user['user_id'], user['login'], session_id)

            return {
                'success': True,
                'user_token': session_id,
                'session_token': session_token,
                'user_id': user['user_id'],
                'username': user['username']
            }
        else:
            return {'success': False, 'error': 'Неверный логин или пароль'}

    def handle_logout_current(self, data):
        user_token = data.get('user_token')
        user_id = data.get('user_id')
        session_token = data.get('session_token', '')

        if session_token:
            user = self.db.get_user_by_session_token(session_token, user_id)
        else:
            user = self.db.get_user_by_token(user_token, user_id)

        if not user:
            return {'success': False, 'error': 'Неверный токен или ID пользователя'}

        self.db.deactivate_session(user_token, user_id)

        return {'success': True}

    def handle_info(self, data):
        user_token = data.get('user_token')
        user_id = data.get('user_id')
        session_token = data.get('session_token', '')

        if session_token:
            user = self.db.get_user_by_session_token(session_token, user_id)
        else:
            user = self.db.get_user_by_token(user_token, user_id)

        if not user:
            return {'success': False, 'error': 'Неверный токен или ID пользователя'}

        if user_token:
            self.db.update_session_last_used(user_token)

        return {
            'success': True,
            'user_id': user['user_id'],
            'username': user['username'],
            'avatar': user['avatar'] if user['avatar'] else None,
        }

    def handle_get_sessions(self, data):
        user_token = data.get('user_token')
        user_id = data.get('user_id')
        session_token = data.get('session_token', '')

        if session_token:
            user = self.db.get_user_by_session_token(session_token, user_id)
        else:
            user = self.db.get_user_by_token(user_token, user_id)

        if not user:
            return {'success': False, 'error': 'Неверный токен или ID пользователя'}

        sessions = self.db.get_user_sessions(user_id)

        formatted_sessions = []
        for session in sessions:
            formatted_sessions.append({
                'session_id': session['session_id'],
                'created_at': session['created_at'],
                'last_used_at': session['last_used_at'],
                'is_active': bool(session['is_active']),
                'is_current': session['session_id'] == user_token
            })

        return {
            'success': True,
            'sessions': formatted_sessions
        }

    def handle_logout_session(self, data):
        user_token = data.get('user_token')
        user_id = data.get('user_id')
        session_token = data.get('session_token', '')
        target_session_id = data.get('target_session_id')

        if session_token:
            user = self.db.get_user_by_session_token(session_token, user_id)
        else:
            user = self.db.get_user_by_token(user_token, user_id)

        if not user:
            return {'success': False, 'error': 'Неверный токен или ID пользователя'}

        if not target_session_id:
            return {'success': False, 'error': 'Не указана сессия для выхода'}

        self.db.deactivate_session(target_session_id, user_id)

        return {'success': True}

    def handle_logout_all_sessions(self, data):
        user_token = data.get('user_token')
        user_id = data.get('user_id')
        session_token = data.get('session_token', '')

        if session_token:
            user = self.db.get_user_by_session_token(session_token, user_id)
        else:
            user = self.db.get_user_by_token(user_token, user_id)

        if not user:
            return {'success': False, 'error': 'Неверный токен или ID пользователя'}

        self.db.deactivate_all_sessions_except(user_id, user_token)

        return {'success': True}

    def handle_get_cleanup_interval(self, data):
        user_token = data.get('user_token')
        user_id = data.get('user_id')
        session_token = data.get('session_token', '')

        if session_token:
            user = self.db.get_user_by_session_token(session_token, user_id)
        else:
            user = self.db.get_user_by_token(user_token, user_id)

        if not user:
            return {'success': False, 'error': 'Неверный токен или ID пользователя'}

        interval = self.db.get_cleanup_interval(user_id)

        return {
            'success': True,
            'cleanup_interval': interval
        }

    def handle_set_cleanup_interval(self, data):
        user_token = data.get('user_token')
        user_id = data.get('user_id')
        session_token = data.get('session_token', '')
        interval = data.get('interval')

        if session_token:
            user = self.db.get_user_by_session_token(session_token, user_id)
        else:
            user = self.db.get_user_by_token(user_token, user_id)

        if not user:
            return {'success': False, 'error': 'Неверный токен или ID пользователя'}

        if interval < 0:
            return {'success': False, 'error': 'Интервал не может быть отрицательным'}

        self.db.set_cleanup_interval(user_id, interval)

        return {'success': True}

    def handle_search_users(self, data):
        user_token = data.get('user_token')
        user_id = data.get('user_id')
        search_query = data.get('search_query', '').strip()
        session_token = data.get('session_token', '')

        if session_token:
            user = self.db.get_user_by_session_token(session_token, user_id)
        else:
            user = self.db.get_user_by_token(user_token, user_id)

        if not user:
            return {'success': False, 'error': 'Неверный токен или ID пользователя'}

        if not search_query:
            return {'success': True, 'users': []}

        query = '''
            select login, username 
            from users 
            where (login like ? or username like ?) 
            and login != ?
            limit 20
        '''
        search_pattern = f"%{search_query}%"
        users = self.db.execute_query(query, (search_pattern, search_pattern, user['login']))

        return {
            'success': True,
            'users': users if users else []
        }

    def handle_get_user_info(self, data):
        user_token = data.get('user_token')
        user_id = data.get('user_id')
        target_login = data.get('target_login')
        session_token = data.get('session_token', '')

        if session_token:
            user = self.db.get_user_by_session_token(session_token, user_id)
        else:
            user = self.db.get_user_by_token(user_token, user_id)

        if not user:
            return {'success': False, 'error': 'Неверный токен или ID пользователя'}

        if not target_login:
            return {'success': False, 'error': 'Не указан логин пользователя'}

        result = self.db.execute_query(
            'select login, username from users where login = ?',
            (target_login,)
        )

        if not result:
            return {'success': False, 'error': 'Пользователь не найден'}

        target_user = result[0]

        contact_result = self.db.execute_query(
            'select * from contacts where contact_owner = ? and contact_login = ?',
            (user['login'], target_login)
        )

        is_contact = bool(contact_result)

        return {
            'success': True,
            'user': {
                'login': target_user['login'],
                'username': target_user['username'],
                'is_contact': is_contact
            }
        }

    def handle_send_message(self, data):
        user_token = data.get('user_token')
        user_id = data.get('user_id')
        receiver_login = data.get('receiver_login')
        text = data.get('text')
        session_token = data.get('session_token', '')

        if session_token:
            user = self.db.get_user_by_session_token(session_token, user_id)
        else:
            user = self.db.get_user_by_token(user_token, user_id)

        if not user:
            return {'success': False, 'error': 'Неверный токен или ID пользователя'}

        query = '''
            insert into messages (sender_login, receiver_login, message_text)
            values (?, ?, ?)
        '''

        if self.db.execute_update(query, (user['login'], receiver_login, text)):
            return {'success': True}
        else:
            return {'success': False, 'error': 'Ошибка при отправке сообщения'}

    def handle_get_messages(self, data):
        user_token = data.get('user_token')
        user_id = data.get('user_id')
        other_user_login = data.get('other_user_login')
        session_token = data.get('session_token', '')

        if session_token:
            user = self.db.get_user_by_session_token(session_token, user_id)
        else:
            user = self.db.get_user_by_token(user_token, user_id)

        if not user:
            return {'success': False, 'error': 'Неверный токен или ID пользователя'}

        query = '''
            select m.*, u.username as sender_name
            from messages m
            join users u on m.sender_login = u.login
            where (m.sender_login = ? and m.receiver_login = ?) 
               or (m.sender_login = ? and m.receiver_login = ?)
            order by m.timestamp asc
        '''

        messages = self.db.execute_query(
            query,
            (user['login'], other_user_login, other_user_login, user['login'])
        )

        return {
            'success': True,
            'messages': messages if messages else []
        }

    def handle_update_profile(self, data):
        user_token = data.get('user_token')
        user_id = data.get('user_id')
        username = data.get('username')
        avatar = data.get('avatar')
        password = data.get('password')
        session_token = data.get('session_token', '')

        if session_token:
            user = self.db.get_user_by_session_token(session_token, user_id)
        else:
            user = self.db.get_user_by_token(user_token, user_id)

        if not user:
            return {'success': False, 'error': 'Неверный токен или ID пользователя'}

        updates = []
        params = []

        if username:
            result = self.db.execute_query(
                'select * from users where username = ? and login != ?',
                (username, user['login'])
            )
            if result:
                return {'success': False, 'error': 'Имя пользователя уже занято'}
            updates.append('username = ?')
            params.append(username)

        if avatar:
            if len(avatar) > 1000000:
                return {'success': False, 'error': 'Аватар слишком большой (максимум 1MB)'}
            updates.append('avatar = ?')
            params.append(avatar)

        if password:
            updates.append('password = ?')
            params.append(password)

            if not username and not avatar:
                self.db.deactivate_all_sessions_except(user_id, user_token)

        if updates:
            params.extend([user['login']])
            query = f'''
                update users 
                set {', '.join(updates)} 
                where login = ?
            '''
            if self.db.execute_update(query, tuple(params)):
                return {'success': True}
            else:
                return {'success': False, 'error': 'Ошибка при обновлении профиля'}

        return {'success': True}

    def handle_add_contact(self, data):
        user_token = data.get('user_token')
        user_id = data.get('user_id')
        contact_login = data.get('contact_login')
        session_token = data.get('session_token', '')

        if session_token:
            user = self.db.get_user_by_session_token(session_token, user_id)
        else:
            user = self.db.get_user_by_token(user_token, user_id)

        if not user:
            return {'success': False, 'error': 'Неверный токен или ID пользователя'}

        result = self.db.execute_query(
            'select * from users where login = ?',
            (contact_login,)
        )
        if not result:
            return {'success': False, 'error': 'Пользователь не найден'}

        if contact_login == user['login']:
            return {'success': False, 'error': 'Нельзя добавить самого себя'}

        result = self.db.execute_query(
            'select * from contacts where contact_owner = ? and contact_login = ?',
            (user['login'], contact_login)
        )
        if result:
            return {'success': False, 'error': 'Контакт уже добавлен'}

        query = '''
            insert into contacts (contact_owner, contact_login) 
            values (?, ?)
        '''

        if self.db.execute_update(query, (user['login'], contact_login)):
            return {'success': True}
        else:
            return {'success': False, 'error': 'Ошибка при добавлении контакта'}

    def handle_get_contacts(self, data):
        user_token = data.get('user_token')
        user_id = data.get('user_id')
        session_token = data.get('session_token', '')

        if session_token:
            user = self.db.get_user_by_session_token(session_token, user_id)
        else:
            user = self.db.get_user_by_token(user_token, user_id)

        if not user:
            return {'success': False, 'error': 'Неверный токен или ID пользователя'}

        query = '''
            select u.login, u.username
            from contacts c 
            join users u on c.contact_login = u.login 
            where c.contact_owner = ?
            order by u.username
        '''

        contacts = self.db.execute_query(query, (user['login'],))

        return {
            'success': True,
            'contacts': contacts if contacts else []
        }

    def handle_get_avatar(self, data):
        user_token = data.get('user_token')
        user_id = data.get('user_id')
        contact_login = data.get('contact_login')
        session_token = data.get('session_token', '')

        if session_token:
            user = self.db.get_user_by_session_token(session_token, user_id)
        else:
            user = self.db.get_user_by_token(user_token, user_id)

        if not user:
            return {'success': False, 'error': 'Неверный токен или ID пользователя'}

        result = self.db.execute_query(
            'select avatar from users where login = ?',
            (contact_login,)
        )

        if result and result[0]['avatar']:
            return {'success': True, 'avatar': result[0]['avatar']}
        else:
            default_avatar_path = AVATARS_DIR / 'default_avatar.jpg'
            if default_avatar_path.exists():
                with open(default_avatar_path, 'rb') as f:
                    avatar_bytes = f.read()
                avatar_base64 = base64.b64encode(avatar_bytes).decode('utf-8')
                return {'success': True, 'avatar': avatar_base64}

            return {'success': True, 'avatar': None}

    def handle_save_contact_settings(self, data):
        user_token = data.get('user_token')
        user_id = data.get('user_id')
        contact_login = data.get('contact_login')
        display_name = data.get('display_name')
        session_token = data.get('session_token', '')

        if session_token:
            user = self.db.get_user_by_session_token(session_token, user_id)
        else:
            user = self.db.get_user_by_token(user_token, user_id)

        if not user:
            return {'success': False, 'error': 'Неверный токен или ID пользователя'}

        query = '''
            insert or replace into contact_settings 
            (user_login, contact_login, display_name)
            values (?, ?, ?)
        '''

        if self.db.execute_update(query, (user['login'], contact_login, display_name)):
            return {'success': True}
        else:
            return {'success': False, 'error': 'Ошибка при сохранении настроек'}

    def handle_get_contact_settings(self, data):
        user_token = data.get('user_token')
        user_id = data.get('user_id')
        session_token = data.get('session_token', '')

        if session_token:
            user = self.db.get_user_by_session_token(session_token, user_id)
        else:
            user = self.db.get_user_by_token(user_token, user_id)

        if not user:
            return {'success': False, 'error': 'Неверный токен или ID пользователя'}

        result = self.db.execute_query(
            'select contact_login, display_name from contact_settings where user_login = ?',
            (user['login'],)
        )

        settings = {}
        if result:
            for row in result:
                settings[row['contact_login']] = {
                    'display_name': row['display_name']
                }

        return {'success': True, 'settings': settings}

    def handle_remove_contact(self, data):
        user_token = data.get('user_token')
        user_id = data.get('user_id')
        contact_login = data.get('contact_login')
        session_token = data.get('session_token', '')

        if session_token:
            user = self.db.get_user_by_session_token(session_token, user_id)
        else:
            user = self.db.get_user_by_token(user_token, user_id)

        if not user:
            return {'success': False, 'error': 'Неверный токен или ID пользователя'}

        query = '''
            delete from contacts 
            where contact_owner = ? and contact_login = ?
        '''

        if self.db.execute_update(query, (user['login'], contact_login)):
            return {'success': True}
        else:
            return {'success': False, 'error': 'Ошибка при удалении контакта'}


def handle_client(client_socket, address):
    print(f"[+] Подключился клиент {address}")

    handler = RequestHandler()

    while True:
        data = b""
        while True:
            chunk = client_socket.recv(4096)
            if not chunk:
                break
            data += chunk
            try:
                request = json.loads(data.decode('utf-8'))
                break
            except:
                continue

        if not data:
            break

        response = handler.handle_request(data)

        response_json = json.dumps(response)
        client_socket.send(response_json.encode('utf-8'))

    client_socket.close()
    print(f"[-] Клиент {address} отключился")


def start_server(host=SERVER_HOST, port=SERVER_PORT):
    start_session_cleanup_timer()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((host, port))
    server_socket.listen(MAX_CONNECTIONS)
    print(f"[*] Сервер запущен на {host}:{port}")
    print(f"[*] Ожидание подключений...")

    while True:
        client_socket, address = server_socket.accept()

        client_thread = threading.Thread(
            target=handle_client,
            args=(client_socket, address),
            daemon=True
        )
        client_thread.start()


if __name__ == '__main__':
    start_server()