import os
import hashlib
import hmac
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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