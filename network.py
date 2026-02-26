import json
import hashlib
import base64
import os
import time
import hmac
from pathlib import Path
from PyQt6.QtCore import QObject, pyqtSignal, QUrl, QTimer, QByteArray, QEventLoop, QSettings
from PyQt6.QtNetwork import QNetworkAccessManager, QNetworkRequest, QNetworkReply
import opaque_ke_py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime, timezone

SERVER_URL = "https://5.35.80.248:5000"


def gen_msg_master_key():
    # - генерируем мастер-ключ
    return os.urandom(64)


def encrypt_master_key(master_key, password):
    # - шифруем мастер-ключ паролем
    salt = os.urandom(32)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000
    )
    key = kdf.derive(password.encode())
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, master_key, None)
    return {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }


def decrypt_master_key(encrypted, password):
    # - расшифровываем мастер-ключ
    salt = base64.b64decode(encrypted['salt'])
    nonce = base64.b64decode(encrypted['nonce'])
    ciphertext = base64.b64decode(encrypted['ciphertext'])
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000
    )
    key = kdf.derive(password.encode())
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


class E2EEMasterKey:
    # -- мастер-ключ для e2ee
    def __init__(self, master_key, salt=None):
        self.master_key = master_key
        self.identity_key = master_key[:32]
        self.encryption_key = master_key[32:48]
        self.derivation_key = master_key[48:64]
        self._derive_static_keypair()

    def _derive_static_keypair(self):
        seed = hmac.new(b'static_keypair', self.identity_key, hashlib.sha256).digest()
        self.private_key = x25519.X25519PrivateKey.from_private_bytes(seed[:32])
        self.public_key = self.private_key.public_key()

    def get_public_key_bytes(self):
        return self.public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


class E2EEContactManager:
    # -- менеджер ключей контактов
    def __init__(self, master_key, api):
        self.master_key = master_key
        self.api = api
        self.contact_keys = {}
        self.own_public_key = master_key.get_public_key_bytes()

    def get_own_public_key(self):
        return self.own_public_key

    def get_contact_public_key(self, contact_login):
        if contact_login in self.contact_keys:
            return self.contact_keys[contact_login]
        response = self.api.network_manager.send_sync_request('get_public_key', {
            'contact_login': contact_login
        })
        if response and response.get('success'):
            pub = base64.b64decode(response['public_key'])
            sig = base64.b64decode(response['signature'])
            if self._verify_contact_key(pub, sig):
                self.contact_keys[contact_login] = pub
                return pub
        return None

    def _verify_contact_key(self, public_key, signature):
        return True

    def publish_own_key(self):
        pub = self.own_public_key
        sig = hmac.new(self.master_key.identity_key, pub, hashlib.sha256).digest()
        self.api.network_manager.send_sync_request('publish_public_key', {
            'public_key': base64.b64encode(pub).decode(),
            'signature': base64.b64encode(sig).decode()
        })


class E2EEMessageHandler:
    # -- обработчик шифрования сообщений
    def __init__(self, master_key, contact_manager):
        self.master_key = master_key
        self.contact_manager = contact_manager

    def encrypt_message(self, plaintext, receiver_login):
        receiver_pub_bytes = self.contact_manager.get_contact_public_key(receiver_login)
        if not receiver_pub_bytes:
            raise Exception(f"Нет публичного ключа для {receiver_login}")

        receiver_public = x25519.X25519PublicKey.from_public_bytes(receiver_pub_bytes)
        shared_secret = self.master_key.private_key.exchange(receiver_public)

        message_key = hmac.new(shared_secret, b'message_key', hashlib.sha256).digest()
        nonce = os.urandom(12)
        aesgcm = AESGCM(message_key)

        own_pub_bytes = self.contact_manager.get_own_public_key()
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), own_pub_bytes)

        signing_key = hmac.new(shared_secret, b'signing', hashlib.sha256).digest()
        data_to_sign = ciphertext + nonce + own_pub_bytes
        signature = hmac.new(signing_key, data_to_sign, hashlib.sha256).digest()

        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'ephemeral_public': base64.b64encode(own_pub_bytes).decode(),
            'signature': base64.b64encode(signature).decode()
        }

    def decrypt_message(self, encrypted_data, contact_login):
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        payload_pub_bytes = base64.b64decode(encrypted_data['ephemeral_public'])
        signature = base64.b64decode(encrypted_data['signature'])

        own_pub = self.contact_manager.get_own_public_key()

        if payload_pub_bytes == own_pub:
            other_pub_bytes = self.contact_manager.get_contact_public_key(contact_login)
            if not other_pub_bytes:
                raise Exception("Нет ключа собеседника для расшифровки своего сообщения")
            other_public_key = x25519.X25519PublicKey.from_public_bytes(other_pub_bytes)
        else:
            other_public_key = x25519.X25519PublicKey.from_public_bytes(payload_pub_bytes)

        shared_secret = self.master_key.private_key.exchange(other_public_key)

        signing_key = hmac.new(shared_secret, b'signing', hashlib.sha256).digest()
        data_to_verify = ciphertext + nonce + payload_pub_bytes
        expected_signature = hmac.new(signing_key, data_to_verify, hashlib.sha256).digest()

        if not hmac.compare_digest(signature, expected_signature):
            return "[Ошибка: Неверная подпись]"

        message_key = hmac.new(shared_secret, b'message_key', hashlib.sha256).digest()
        aesgcm = AESGCM(message_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, payload_pub_bytes)
        return plaintext.decode('utf-8')


class Contact:
    # -- контакт пользователя
    def __init__(self, login, username, user_id, avatar_version=0, display_name=None):
        self.login = login
        self.username = username
        self.user_id = user_id
        self.avatar_version = avatar_version
        self.display_name = display_name or username
        self.last_avatar_check = 0
        self.public_key = None

    def get_display_name(self):
        return self.display_name

    def needs_avatar_check(self):
        return time.time() - self.last_avatar_check > 60

    def update_avatar_check_time(self):
        self.last_avatar_check = time.time()


class SSEListener(QObject):
    # -- слушатель событий от сервера
    message_received = pyqtSignal(dict)
    avatar_updated = pyqtSignal(dict)
    connection_status = pyqtSignal(bool)

    def __init__(self, session_token, user_id, user_login):
        super().__init__()
        self.session_token = session_token
        self.user_id = user_id
        self.user_login = user_login
        self.nam = QNetworkAccessManager()
        self.reply = None
        self.buffer = b""
        self.active = False

    def start(self):
        self.active = True
        url = QUrl(f"{SERVER_URL}/api/events")
        request = QNetworkRequest(url)
        request.setHeader(QNetworkRequest.KnownHeaders.ContentTypeHeader, "text/event-stream")
        request.setRawHeader(b"X-User-Id", str(self.user_id).encode())
        request.setRawHeader(b"X-Session-Token", self.session_token.encode())
        from network import messenger_api
        if messenger_api and messenger_api.device_id:
            request.setRawHeader(b"X-Device-ID", messenger_api.device_id.encode())
        request.setAttribute(QNetworkRequest.Attribute.CacheLoadControlAttribute,
                             QNetworkRequest.CacheLoadControl.AlwaysNetwork)
        self.reply = self.nam.get(request)
        self.reply.readyRead.connect(self._on_ready_read)
        self.reply.finished.connect(self._on_finished)
        self.connection_status.emit(True)

    def stop(self):
        self.active = False
        if self.reply:
            self.reply.abort()
            self.reply.deleteLater()
            self.reply = None

    def _on_ready_read(self):
        if not self.reply:
            return
        data = self.reply.readAll().data()
        self.buffer += data
        while b"\n\n" in self.buffer:
            part, self.buffer = self.buffer.split(b"\n\n", 1)
            self._parse_sse_event(part)

    def _parse_sse_event(self, chunk):
        lines = chunk.decode('utf-8', errors='ignore').split('\n')
        event_type = None
        data = None
        for line in lines:
            if line.startswith("event:"):
                event_type = line[6:].strip()
            elif line.startswith("data:"):
                data = line[5:].strip()
        if data and event_type:
            json_data = json.loads(data)
            if event_type == 'new_message':
                self.message_received.emit(json_data)
            elif event_type == 'avatar_updated':
                self.avatar_updated.emit(json_data)

    def _on_finished(self):
        if self.active:
            self.connection_status.emit(False)
            QTimer.singleShot(1000, self.start)


class SyncHTTPRequest:
    # -- синхронный https запрос
    @staticmethod
    def post(endpoint, data=None):
        url = QUrl(f"{SERVER_URL}/api/{endpoint}")
        request = QNetworkRequest(url)
        request.setHeader(QNetworkRequest.KnownHeaders.ContentTypeHeader, "application/json")
        from network import messenger_api
        if messenger_api and messenger_api.device_id:
            request.setRawHeader(b"X-Device-ID", messenger_api.device_id.encode())
        if data:
            if 'session_token' in data:
                request.setRawHeader(b"X-Session-Token", str(data['session_token']).encode())
                del data['session_token']
            if 'user_id' in data:
                request.setRawHeader(b"X-User-Id", str(data['user_id']).encode())
                del data['user_id']
            if 'user_token' in data:
                request.setRawHeader(b"X-User-Token", str(data['user_token']).encode())
                del data['user_token']
        json_data = QByteArray(json.dumps(data, ensure_ascii=False).encode('utf-8')) if data else QByteArray()
        nam = QNetworkAccessManager()
        reply = nam.post(request, json_data)
        loop = QEventLoop()
        reply.finished.connect(loop.quit)
        loop.exec()

        status_code = reply.attribute(QNetworkRequest.Attribute.HttpStatusCodeAttribute)
        if status_code and status_code != 200:
            response_data = reply.readAll().data()
            json_response = json.loads(response_data)
            error_msg = json_response.get('error', f'HTTPS ошибка {status_code}')
            return {'success': False, 'error': error_msg}

        if reply.error() != QNetworkReply.NetworkError.NoError:
            return {'success': False, 'error': reply.errorString()}

        response_data = reply.readAll().data()
        return json.loads(response_data)


class FileCache:
    # -- кэш для файлов
    def __init__(self, user_id):
        self.user_id = user_id
        self.cache_dir = Path(f'files_cache/{user_id}')
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_file = self.cache_dir / 'metadata.json'
        self.metadata = self.load_metadata()

    def load_metadata(self):
        if self.metadata_file.exists():
            with open(self.metadata_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}

    def save_metadata(self):
        with open(self.metadata_file, 'w', encoding='utf-8') as f:
            json.dump(self.metadata, f, ensure_ascii=False, indent=2)

    def get_file_path(self, file_id, file_name):
        safe_name = "".join(c for c in file_name if c.isalnum() or c in '._- ')[:50]
        return self.cache_dir / f"{file_id}_{safe_name}"

    def has_file(self, file_id):
        return str(file_id) in self.metadata

    def save_file(self, file_id, file_name, file_type, file_size, file_data, thumbnail_data=None):
        file_path = self.get_file_path(file_id, file_name)
        with open(file_path, 'wb') as f:
            f.write(file_data)
        if thumbnail_data:
            thumb_path = self.cache_dir / f"thumb_{file_id}.jpg"
            with open(thumb_path, 'wb') as f:
                f.write(thumbnail_data)
        self.metadata[str(file_id)] = {
            'file_name': file_name,
            'file_type': file_type,
            'file_size': file_size,
            'file_path': str(file_path),
            'thumbnail_path': str(thumb_path) if thumbnail_data else None,
            'timestamp': time.time()
        }
        self.save_metadata()
        return file_path

    def get_file_info(self, file_id):
        return self.metadata.get(str(file_id))

    def get_file_data(self, file_id):
        info = self.get_file_info(file_id)
        if info and 'file_path' in info:
            with open(info['file_path'], 'rb') as f:
                return f.read()
        return None

    def get_thumbnail_data(self, file_id):
        info = self.get_file_info(file_id)
        if info and info.get('thumbnail_path'):
            with open(info['thumbnail_path'], 'rb') as f:
                return f.read()
        return None

    def clear_cache(self):
        import shutil
        shutil.rmtree(self.cache_dir, ignore_errors=True)


class NetworkManager(QObject):
    # -- менеджер сети
    message_received = pyqtSignal(dict)
    connection_status_changed = pyqtSignal(bool)
    avatar_updated = pyqtSignal(dict)

    def __init__(self, host='5.35.80.248', port=5000):
        super().__init__()
        self.host = host
        self.port = port
        self.base_url = f"https://{host}:{port}"
        self.session_token = None
        self.user_token = None
        self.user_id = None
        self.user_login = None
        self.sse_listener = None
        self.avatars_dir = Path('avatars')
        self.avatars_dir.mkdir(exist_ok=True)

    def set_credentials(self, session_token=None, user_token=None, user_id=None, user_login=None):
        if session_token is not None:
            self.session_token = session_token
        if user_token is not None:
            self.user_token = user_token
        if user_id is not None:
            self.user_id = user_id
        if user_login is not None:
            self.user_login = user_login

    def start_event_listener(self):
        self.stop_event_listener()
        self.sse_listener = SSEListener(self.session_token, self.user_id, self.user_login)
        self.sse_listener.message_received.connect(self.message_received)
        self.sse_listener.avatar_updated.connect(self.avatar_updated)
        self.sse_listener.connection_status.connect(self.connection_status_changed)
        self.sse_listener.start()

    def stop_event_listener(self):
        if self.sse_listener:
            self.sse_listener.stop()
            self.sse_listener.deleteLater()
            self.sse_listener = None

    def send_sync_request(self, endpoint, data):
        if self.session_token and 'session_token' not in data:
            data['session_token'] = self.session_token
        if self.user_token and 'user_token' not in data:
            data['user_token'] = self.user_token
        if self.user_id and 'user_id' not in data:
            data['user_id'] = self.user_id
        return SyncHTTPRequest.post(endpoint, data)

    def get_avatar_path(self, user_id, avatar_version):
        return self.avatars_dir / f"{user_id}_{avatar_version}.jpg"

    def has_avatar_cached(self, user_id, avatar_version):
        return self.get_avatar_path(user_id, avatar_version).exists()

    def save_avatar_to_cache(self, user_id, avatar_version, avatar_data):
        with open(self.get_avatar_path(user_id, avatar_version), 'wb') as f:
            f.write(avatar_data)

    def get_avatar_from_cache(self, user_id, avatar_version):
        p = self.get_avatar_path(user_id, avatar_version)
        if p.exists():
            with open(p, 'rb') as f:
                return f.read()
        return None

    def remove_old_avatar(self, user_id, old_version):
        p = self.get_avatar_path(user_id, old_version)
        if p.exists():
            p.unlink()


class MessengerAPI:
    # -- главный api для работы с сервером
    def __init__(self, host='5.35.80.248', port=5000):
        self.network_manager = NetworkManager(host, port)
        self.file_cache = None
        self.login_in_progress = False
        self.device_id = None
        self.user_login = None
        self.e2ee_master_key = None
        self.e2ee_contact_manager = None
        self.e2ee_message_handler = None
        self.encrypted_master_key = None

    def init_device_id(self):
        settings = QSettings("Phantom", "Messenger")
        device_id = settings.value("device_id", "")
        if not device_id:
            import uuid
            device_id = str(uuid.uuid4())
            settings.setValue("device_id", device_id)
        self.device_id = device_id

    def set_user_credentials(self, session_token, user_id, user_login=None):
        if user_login is not None:
            self.user_login = user_login
        self.network_manager.set_credentials(session_token=session_token, user_id=user_id, user_login=self.user_login)
        if user_id:
            self.file_cache = FileCache(user_id)

    def set_session_token(self, session_token):
        self.network_manager.session_token = session_token

    def auth(self, token, user_id):
        data = {'user_token': token, 'user_id': user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        response = self.network_manager.send_sync_request('auth', data)
        if response and response.get('success'):
            self.network_manager.set_credentials(session_token=self.network_manager.session_token, user_token=token,
                                                 user_id=user_id)
            self.network_manager.start_event_listener()
        return response

    def init_e2ee(self, master_key):
        self.e2ee_master_key = E2EEMasterKey(master_key)
        self.e2ee_contact_manager = E2EEContactManager(self.e2ee_master_key, self)
        self.e2ee_message_handler = E2EEMessageHandler(self.e2ee_master_key, self.e2ee_contact_manager)
        self.e2ee_contact_manager.publish_own_key()

    def send_message(self, token, user_id, receiver_login, text='', file_id=None):
        if self.e2ee_message_handler and text:
            encrypted = self.e2ee_message_handler.encrypt_message(text, receiver_login)
            text = json.dumps({'type': 'e2ee', 'data': encrypted})
        client_timestamp = datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
        nonce = os.urandom(8).hex()
        data = {
            'user_token': token,
            'user_id': user_id,
            'receiver_login': receiver_login,
            'text': text,
            'file_id': file_id,
            'client_timestamp': client_timestamp,
            'nonce': nonce
        }
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('send_message', data)

    def get_messages(self, token, user_id, other_user_login):
        data = {'user_token': token, 'user_id': user_id, 'other_user_login': other_user_login}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_messages', data)

    def get_messages_since(self, token, user_id, contact_login, since_id):
        data = {'user_token': token, 'user_id': user_id, 'contact_login': contact_login, 'since_id': since_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_messages_since', data)

    def logout_current(self, token, user_id):
        data = {'user_token': token, 'user_id': user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        resp = self.network_manager.send_sync_request('logout_current', data)
        self.network_manager.stop_event_listener()
        self.file_cache = None
        return resp

    def info(self, token, user_id):
        data = {'user_token': token, 'user_id': user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('info', data)

    def get_sessions(self, token, user_id):
        data = {'user_token': token, 'user_id': user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_sessions', data)

    def logout_session(self, token, user_id, target_session_id):
        data = {'user_token': token, 'user_id': user_id, 'target_session_id': target_session_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('logout_session', data)

    def logout_all_sessions(self, token, user_id):
        data = {'user_token': token, 'user_id': user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('logout_all_sessions', data)

    def get_cleanup_interval(self, token, user_id):
        data = {'user_token': token, 'user_id': user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_cleanup_interval', data)

    def set_cleanup_interval(self, token, user_id, interval):
        data = {'user_token': token, 'user_id': user_id, 'interval': interval}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('set_cleanup_interval', data)

    def _encrypt_file_key(self, file_key):
        if not self.e2ee_master_key:
            raise Exception("E2EE не инициализирован")
        nonce = os.urandom(12)
        aesgcm = AESGCM(self.e2ee_master_key.encryption_key)
        cipher = aesgcm.encrypt(nonce, file_key, None)
        combined = nonce + cipher
        return base64.b64encode(combined).decode('utf-8')

    def _decrypt_file_key(self, encrypted_key):
        if not self.e2ee_master_key:
            raise Exception("E2EE не инициализирован")
        combined = base64.b64decode(encrypted_key)
        nonce = combined[:12]
        cipher = combined[12:]
        aesgcm = AESGCM(self.e2ee_master_key.encryption_key)
        return aesgcm.decrypt(nonce, cipher, None)

    def encrypt_file_data(self, file_data, thumbnail_data):
        file_key = os.urandom(32)

        nonce_file = os.urandom(12)
        aesgcm = AESGCM(file_key)
        ciphertext = aesgcm.encrypt(nonce_file, file_data, None)

        result = {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce_file': base64.b64encode(nonce_file).decode('utf-8'),
            'encrypted_key': self._encrypt_file_key(file_key),
            'file_key': base64.b64encode(file_key).decode('utf-8')
        }

        if thumbnail_data:
            nonce_thumb = os.urandom(12)
            thumb_cipher = aesgcm.encrypt(nonce_thumb, thumbnail_data, None)
            result['thumbnail'] = base64.b64encode(thumb_cipher).decode('utf-8')
            result['nonce_thumbnail'] = base64.b64encode(nonce_thumb).decode('utf-8')

        return result

    def decrypt_file_data(self, ciphertext, nonce, encrypted_key):
        file_key = self._decrypt_file_key(encrypted_key)
        aesgcm = AESGCM(file_key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def upload_file(self, token, user_id, file_data, file_name, file_type,
                    is_image_only=False, encrypted_key=None, nonce_file=None,
                    thumbnail=None, nonce_thumbnail=None):
        data = {
            'user_token': token,
            'user_id': user_id,
            'file_data': file_data,
            'file_name': file_name,
            'file_type': file_type,
            'is_image_only': is_image_only
        }
        if encrypted_key:
            data['encrypted_key'] = encrypted_key
            data['nonce_file'] = nonce_file
            data['is_encrypted'] = 1
        if thumbnail:
            data['thumbnail'] = thumbnail
        if nonce_thumbnail:
            data['nonce_thumbnail'] = nonce_thumbnail

        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('upload_file', data)

    def get_file(self, token, user_id, file_id, include_data=True, include_thumbnail=False):
        data = {
            'user_token': token,
            'user_id': user_id,
            'file_id': file_id,
            'include_data': include_data,
            'include_thumbnail': include_thumbnail
        }
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_file', data)

    def update_profile(self, token, user_id, username=None, avatar=None):
        data = {'user_token': token, 'user_id': user_id}
        if username:
            data['username'] = username
        if avatar:
            data['avatar'] = avatar
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('update_profile', data)

    def add_contact(self, token, user_id, contact_login):
        data = {'user_token': token, 'user_id': user_id, 'contact_login': contact_login}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('add_contact', data)

    def get_contacts(self, token, user_id):
        data = {'user_token': token, 'user_id': user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_contacts', data)

    def get_avatar_versions(self, token, user_id, user_ids):
        data = {'user_token': token, 'user_id': user_id, 'user_ids': user_ids}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_avatar_versions', data)

    def get_avatar(self, token, user_id, target_user_id):
        data = {'user_token': token, 'user_id': user_id, 'target_user_id': target_user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_avatar', data)

    def save_contact_settings(self, token, user_id, contact_login, display_name):
        data = {'user_token': token, 'user_id': user_id, 'contact_login': contact_login, 'display_name': display_name}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('save_contact_settings', data)

    def get_contact_settings(self, token, user_id):
        data = {'user_token': token, 'user_id': user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_contact_settings', data)

    def remove_contact(self, token, user_id, contact_login):
        data = {'user_token': token, 'user_id': user_id, 'contact_login': contact_login}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('remove_contact', data)

    def search_users(self, token, user_id, search_query):
        data = {'user_token': token, 'user_id': user_id, 'search_query': search_query}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('search_users', data)

    def disconnect(self):
        self.network_manager.stop_event_listener()
        self.file_cache = None

    def _handle_register_start(self, login, username, password, callback, response):
        if not response or not response.get('success'):
            callback(response)
            return

        client_reg_start = opaque_ke_py.client_registration_start(password.encode('utf-8'))
        registration_request = client_reg_start.get_message()
        client_reg_state = client_reg_start.get_state()

        make_server_request_async('opaque/register/finish', {
            'login': login,
            'username': username,
            'registration_request': base64.b64encode(registration_request).decode('utf-8')
        }, lambda resp: self._handle_register_finish(login, username, password, client_reg_state, callback, resp))

    def _handle_register_finish(self, login, username, password, client_reg_state, callback, response):
        if not response or not response.get('success'):
            callback(response)
            return

        server_response = base64.b64decode(response['server_response'])
        client_reg_finish = opaque_ke_py.client_registration_finish(password.encode('utf-8'), client_reg_state,
                                                                    server_response)
        registration_upload = client_reg_finish.get_message()

        master_key = gen_msg_master_key()
        encrypted = encrypt_master_key(master_key, password)
        encrypted_master_key = json.dumps(encrypted)

        make_server_request_async('opaque/register/upload', {
            'login': login,
            'username': username,
            'registration_upload': base64.b64encode(registration_upload).decode('utf-8'),
            'encrypted_master_key': encrypted_master_key
        }, lambda resp: self._handle_register_upload(login, username, password, master_key, callback, resp))

    def _handle_register_upload(self, login, username, password, master_key, callback, response):
        if response and response.get('success'):
            user_id = response['user_id']
            self.init_e2ee(master_key)
            callback(response)
        else:
            callback(response)

    def opaque_register_async(self, login, username, password, callback):
        make_server_request_async('opaque/register/start', {
            'login': login,
            'username': username
        }, lambda resp: self._handle_register_start(login, username, password, callback, resp))

    def _handle_login_start(self, login, password, client_login_state, callback, response):
        if not response or not response.get('success'):
            self.login_in_progress = False
            self.network_manager.stop_event_listener()
            callback(response)
            return

        state_id = response['state_id']
        credential_response = base64.b64decode(response['credential_response'])

        try:
            client_login_finish = opaque_ke_py.client_login_finish(password.encode('utf-8'), client_login_state,
                                                                   credential_response)
            credential_finalization = client_login_finish.get_message()
        except Exception as e:
            self.login_in_progress = False
            self.network_manager.stop_event_listener()
            callback({'success': False, 'error': 'Неверный логин или пароль'})

            def handle_failed_response(failed_response):
                self.login_in_progress = False
                self.network_manager.stop_event_listener()
                if failed_response and failed_response.get('blocked'):
                    callback({'success': False, 'error': failed_response.get('error')})
                else:
                    callback({'success': False, 'error': 'Неверный логин или пароль'})
            make_server_request_async('opaque/login/failed', {
                'login': login
            }, handle_failed_response)
            return

        make_server_request_async('opaque/login/finish', {
            'state_id': state_id,
            'credential_finalization': base64.b64encode(credential_finalization).decode('utf-8')
        }, lambda resp: self._handle_login_finish(login, password, callback, resp))

    def _handle_login_finish(self, login, password, callback, response):
        if response and response.get('success'):
            user_id = response['user_id']
            self.set_user_credentials(response['session_token'], user_id, login)
            encrypted_master_key_str = response.get('encrypted_master_key')
            if encrypted_master_key_str:
                encrypted = json.loads(encrypted_master_key_str)
                master_key = decrypt_master_key(encrypted, password)
                self.init_e2ee(master_key)
            self.network_manager.start_event_listener()
            self.login_in_progress = False
            callback(response)
        else:
            self.login_in_progress = False
            callback(response)

    def opaque_login_async(self, login, password, callback):
        if self.login_in_progress:
            callback({'success': False, 'error': 'Логин уже выполняется'})
            return
        self.login_in_progress = True

        client_login_start = opaque_ke_py.client_login_start(password.encode('utf-8'))
        credential_request = client_login_start.get_message()
        client_login_state = client_login_start.get_state()

        make_server_request_async('opaque/login/start', {
            'login': login,
            'credential_request': base64.b64encode(credential_request).decode('utf-8')
        }, lambda resp: self._handle_login_start(login, password, client_login_state, callback, resp))

    def _handle_change_password_server_response(self, new_password, client_reg_state, callback, response):
        if not response or not response.get('success'):
            callback(response)
            return

        server_response = base64.b64decode(response['server_response'])
        client_reg_finish = opaque_ke_py.client_registration_finish(new_password.encode('utf-8'), client_reg_state,
                                                                    server_response)
        registration_upload = client_reg_finish.get_message()

        master_key = self.e2ee_master_key.master_key
        encrypted_new = encrypt_master_key(master_key, new_password)
        encrypted_master_key_new = json.dumps(encrypted_new)

        make_server_request_async('opaque/change_password/upload', {
            'registration_upload': base64.b64encode(registration_upload).decode('utf-8'),
            'encrypted_master_key': encrypted_master_key_new
        }, lambda resp: self._handle_change_password_upload(callback, resp))

    def _handle_change_password_upload(self, callback, response):
        if response and response.get('success'):
            callback({'success': True})
        else:
            callback(response)

    def opaque_change_password_async(self, new_password, callback):
        if not self.e2ee_master_key:
            callback({'success': False, 'error': 'E2EE не инициализирован'})
            return

        client_reg_start = opaque_ke_py.client_registration_start(new_password.encode('utf-8'))
        client_reg_state = client_reg_start.get_state()
        registration_request = client_reg_start.get_message()

        make_server_request_async('opaque/change_password/get_server_response', {
            'registration_request': base64.b64encode(registration_request).decode('utf-8')
        }, lambda resp: self._handle_change_password_server_response(new_password, client_reg_state, callback, resp))


messenger_api = MessengerAPI()


def make_server_request_async(endpoint, data=None, callback=None):
    if data is None:
        data = {}
    if callback is None:
        callback = lambda x: None
    response = messenger_api.network_manager.send_sync_request(endpoint, data)
    callback(response)