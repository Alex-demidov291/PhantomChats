import socket
import threading
import json
import sqlite3
import uuid
import datetime
import os
import hashlib
import base64
from pathlib import Path

SERVER_HOST = '0.0.0.0'
SERVER_PORT = 5000
MAX_CONNECTIONS = 100
BUFFER_SIZE = 4096
active_connections = {}

# создаем папку для аватарок если ее нет
AVATARS_DIR = Path('avatars')
AVATARS_DIR.mkdir(exist_ok=True)


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


# работа с базой данных
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
        conn.commit()
        conn.close()

    def get_user_by_token(self, user_token, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('select * from users where user_token = ? and user_id = ?',
                       (user_token, user_id))
        user = cursor.fetchone()
        conn.close()
        if user:
            return dict(user)
        return None

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


# обработка запросов
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

            return {
                'success': True,
                'user_token': user['user_token'],
                'user_id': user['user_id'],
                'username': user['username']
            }
        else:
            return {'success': False, 'error': 'Неверный логин или пароль'}

    def handle_info(self, data):
        user_token = data.get('user_token')
        user_id = data.get('user_id')

        user = self.db.get_user_by_token(user_token, user_id)
        if not user:
            return {'success': False, 'error': 'Неверный токен или ID пользователя'}

        return {
            'success': True,
            'user_id': user['user_id'],
            'username': user['username'],
            'avatar': user['avatar'] if user['avatar'] else None,
        }

    def handle_search_users(self, data):
        user_token = data.get('user_token')
        user_id = data.get('user_id')
        search_query = data.get('search_query', '').strip()

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

        user = self.db.get_user_by_token(user_token, user_id)

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

        user = self.db.get_user_by_token(user_token, user_id)

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

        if updates:
            params.extend([user_token, user_id])
            query = f'''
                update users 
                set {', '.join(updates)} 
                where user_token = ? and user_id = ?
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

        user = self.db.get_user_by_token(user_token, user_id)

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

        user = self.db.get_user_by_token(user_token, user_id)
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

        user = self.db.get_user_by_token(user_token, user_id)

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

        user = self.db.get_user_by_token(user_token, user_id)
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