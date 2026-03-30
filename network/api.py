import json
import os
import base64
from datetime import datetime, timezone
from PyQt6.QtCore import QSettings
import opaque_ke_py
from network.manager import NetworkManager
from network.cache import FileCache
from network.crypto import (
    E2EEMasterKey, E2EEContactManager, E2EEMessageHandler,
    gen_msg_master_key, encrypt_master_key, decrypt_master_key
)
from network.transport import AsyncHTTPRequest

class MessengerAPI:
    def __init__(self, host='155.212.132.185', port=5000):
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

    def get_user_info(self, session_id, user_id, target_login):
        data = {'session_id': session_id, 'user_id': user_id, 'target_login': target_login}
        return self.network_manager.send_sync_request('get_user_info', data)

    def set_user_credentials(self, session_id, user_id, user_login=None):
        if user_login is not None:
            self.user_login = user_login
        self.network_manager.set_credentials(session_id=session_id, user_id=user_id, user_login=self.user_login)
        if user_id:
            self.file_cache = FileCache(user_id)

    def auth(self, session_id, user_id):
        data = {'session_id': session_id, 'user_id': user_id}
        response = self.network_manager.send_sync_request('auth', data)
        if response and response.get('success'):
            self.network_manager.set_credentials(session_id=session_id, user_id=user_id)
            self.network_manager.start_event_listener()
        return response

    def init_e2ee(self, master_key):
        self.e2ee_master_key = E2EEMasterKey(master_key)
        self.e2ee_contact_manager = E2EEContactManager(self.e2ee_master_key, self)
        self.e2ee_message_handler = E2EEMessageHandler(self.e2ee_master_key, self.e2ee_contact_manager)
        self.e2ee_contact_manager.publish_own_key()

    def send_message(self, session_id, user_id, receiver_login, text='', file_id=None):
        if self.e2ee_message_handler and text:
            encrypted = self.e2ee_message_handler.encrypt_message(text, receiver_login)
            text = json.dumps({'type': 'e2ee', 'data': encrypted})
        client_timestamp = datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
        nonce = os.urandom(8).hex()
        data = {
            'session_id': session_id,
            'user_id': user_id,
            'receiver_login': receiver_login,
            'text': text,
            'file_id': file_id,
            'client_timestamp': client_timestamp,
            'nonce': nonce
        }
        return self.network_manager.send_sync_request('send_message', data)

    def get_messages(self, session_id, user_id, other_user_login):
        data = {'session_id': session_id, 'user_id': user_id, 'other_user_login': other_user_login}
        return self.network_manager.send_sync_request('get_messages', data)

    def get_messages_since(self, session_id, user_id, contact_login, since_id):
        data = {'session_id': session_id, 'user_id': user_id, 'contact_login': contact_login, 'since_id': since_id}
        return self.network_manager.send_sync_request('get_messages_since', data)

    def logout_current(self, session_id, user_id):
        data = {'session_id': session_id, 'user_id': user_id}
        resp = self.network_manager.send_sync_request('logout_current', data)
        self.network_manager.stop_event_listener()
        self.file_cache = None
        return resp

    def info(self, session_id, user_id):
        data = {'session_id': session_id, 'user_id': user_id}
        return self.network_manager.send_sync_request('info', data)

    def get_sessions(self, session_id, user_id):
        data = {'session_id': session_id, 'user_id': user_id}
        return self.network_manager.send_sync_request('get_sessions', data)

    def logout_session(self, session_id, user_id, target_session_id):
        data = {'session_id': session_id, 'user_id': user_id, 'target_session_id': target_session_id}
        return self.network_manager.send_sync_request('logout_session', data)

    def logout_all_sessions(self, session_id, user_id):
        data = {'session_id': session_id, 'user_id': user_id}
        return self.network_manager.send_sync_request('logout_all_sessions', data)

    def get_cleanup_interval(self, session_id, user_id):
        data = {'session_id': session_id, 'user_id': user_id}
        return self.network_manager.send_sync_request('get_cleanup_interval', data)

    def set_cleanup_interval(self, session_id, user_id, interval):
        data = {'session_id': session_id, 'user_id': user_id, 'interval': interval}
        return self.network_manager.send_sync_request('set_cleanup_interval', data)

    def _encrypt_file_key(self, file_key):
        if not self.e2ee_master_key:
            raise Exception("E2EE не инициализирован")
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = os.urandom(12)
        aesgcm = AESGCM(self.e2ee_master_key.encryption_key)
        cipher = aesgcm.encrypt(nonce, file_key, None)
        combined = nonce + cipher
        return base64.b64encode(combined).decode('utf-8')

    def _decrypt_file_key(self, encrypted_key):
        if not self.e2ee_master_key:
            raise Exception("E2EE не инициализирован")
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        combined = base64.b64decode(encrypted_key)
        nonce = combined[:12]
        cipher = combined[12:]
        aesgcm = AESGCM(self.e2ee_master_key.encryption_key)
        return aesgcm.decrypt(nonce, cipher, None)

    def encrypt_file_data(self, file_data, thumbnail_data, receiver_login=None, callback=None):
        if not self.e2ee_master_key:
            raise Exception("E2EE не инициализирован")
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        file_key = os.urandom(32)
        nonce_file = os.urandom(12)
        aesgcm = AESGCM(file_key)
        ciphertext = aesgcm.encrypt(nonce_file, file_data, None)

        encrypted_key_sender = self._encrypt_file_key(file_key)

        result = {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce_file': base64.b64encode(nonce_file).decode('utf-8'),
            'encrypted_key': json.dumps({'s': encrypted_key_sender}),
        }

        if thumbnail_data:
            nonce_thumb = os.urandom(12)
            thumb_cipher = aesgcm.encrypt(nonce_thumb, thumbnail_data, None)
            result['thumbnail'] = base64.b64encode(thumb_cipher).decode('utf-8')
            result['nonce_thumbnail'] = base64.b64encode(nonce_thumb).decode('utf-8')

        if receiver_login and self.e2ee_contact_manager:
            def on_key_loaded(pub_key):
                if pub_key:
                    try:
                        encrypted_key_receiver = self.e2ee_master_key.encrypt_file_key_for_recipient(
                            file_key, pub_key
                        )
                        bundle = json.loads(result['encrypted_key'])
                        bundle['r'] = encrypted_key_receiver
                        result['encrypted_key'] = json.dumps(bundle)
                    except Exception as e:
                        print(f"Ошибка шифрования для получателя: {e}")
                if callback:
                    callback(result)

            pub_key = self.e2ee_contact_manager.contact_keys.get(receiver_login)
            if pub_key:
                on_key_loaded(pub_key)
            else:
                self.e2ee_contact_manager.get_contact_public_key_async(receiver_login, on_key_loaded)
        else:
            if callback:
                callback(result)

        return result if not callback else None

    def _resolve_file_key(self, encrypted_key_str, sender_login=None):
        if not self.e2ee_master_key:
            raise Exception("E2EE не инициализирован")

        try:
            bundle = json.loads(encrypted_key_str)
            if isinstance(bundle, dict):
                if 's' in bundle:
                    try:
                        return self._decrypt_file_key(bundle['s'])
                    except Exception:
                        pass

                if 'r' in bundle and sender_login and self.e2ee_contact_manager:
                    sender_pub = self.e2ee_contact_manager.contact_keys.get(sender_login)
                    if sender_pub:
                        return self.e2ee_master_key.decrypt_file_key_from_sender(
                            bundle['r'], sender_pub
                        )
        except (json.JSONDecodeError, Exception):
            pass
        return self._decrypt_file_key(encrypted_key_str)

    def decrypt_file_data(self, ciphertext, nonce, encrypted_key, sender_login=None):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        file_key = self._resolve_file_key(encrypted_key, sender_login)
        aesgcm = AESGCM(file_key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def upload_file(self, session_id, user_id, file_data, file_name, file_type,
                    is_image_only=False, encrypted_key=None, nonce_file=None,
                    thumbnail=None, nonce_thumbnail=None):
        data = {
            'session_id': session_id,
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
        return self.network_manager.send_sync_request('upload_file', data)

    def get_file(self, session_id, user_id, file_id, include_data=True, include_thumbnail=False):
        data = {
            'session_id': session_id,
            'user_id': user_id,
            'file_id': file_id,
            'include_data': include_data,
            'include_thumbnail': include_thumbnail
        }
        return self.network_manager.send_sync_request('get_file', data)

    def update_profile(self, session_id, user_id, username=None, avatar=None):
        data = {'session_id': session_id, 'user_id': user_id}
        if username:
            data['username'] = username
        if avatar:
            data['avatar'] = avatar
        return self.network_manager.send_sync_request('update_profile', data)

    def add_contact(self, session_id, user_id, contact_login):
        data = {'session_id': session_id, 'user_id': user_id, 'contact_login': contact_login}
        return self.network_manager.send_sync_request('add_contact', data)

    def get_contacts(self, session_id, user_id):
        data = {'session_id': session_id, 'user_id': user_id}
        return self.network_manager.send_sync_request('get_contacts', data)

    def get_avatar_versions(self, session_id, user_id, user_ids):
        data = {'session_id': session_id, 'user_id': user_id, 'user_ids': user_ids}
        return self.network_manager.send_sync_request('get_avatar_versions', data)

    def get_avatar(self, session_id, user_id, target_user_id):
        data = {'session_id': session_id, 'user_id': user_id, 'target_user_id': target_user_id}
        return self.network_manager.send_sync_request('get_avatar', data)

    def save_contact_settings(self, session_id, user_id, contact_login, display_name):
        data = {'session_id': session_id, 'user_id': user_id, 'contact_login': contact_login, 'display_name': display_name}
        return self.network_manager.send_sync_request('save_contact_settings', data)

    def get_contact_settings(self, session_id, user_id):
        data = {'session_id': session_id, 'user_id': user_id}
        return self.network_manager.send_sync_request('get_contact_settings', data)

    def remove_contact(self, session_id, user_id, contact_login):
        data = {'session_id': session_id, 'user_id': user_id, 'contact_login': contact_login}
        return self.network_manager.send_sync_request('remove_contact', data)

    def search_users(self, session_id, user_id, search_query):
        data = {'session_id': session_id, 'user_id': user_id, 'search_query': search_query}
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
            session_id = response['session_id']
            self.set_user_credentials(session_id, user_id, login)
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

    payload = dict(data)
    nm = messenger_api.network_manager
    if nm.session_id and 'session_id' not in payload:
        payload['session_id'] = nm.session_id
    if nm.user_id and 'user_id' not in payload:
        payload['user_id'] = nm.user_id

    AsyncHTTPRequest(endpoint, payload, callback)