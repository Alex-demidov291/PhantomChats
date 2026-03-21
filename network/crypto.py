import os
import json
import time
import hashlib
import hmac
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature


class KeyChangedError(Exception):
    def __init__(self, contact_login, old_x25519_b64, new_x25519_b64, new_key_bytes):
        self.contact_login = contact_login
        self.old_x25519_b64 = old_x25519_b64
        self.new_x25519_b64 = new_x25519_b64
        self.new_key_bytes = new_key_bytes
        super().__init__(f"Ключ контакта '{contact_login}' изменился")


def gen_msg_master_key():
    return os.urandom(64)


def encrypt_master_key(master_key, password):
    sol = os.urandom(32)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=sol, iterations=600000)
    kluch = kdf.derive(password.encode())
    nonce = os.urandom(12)
    shifr = AESGCM(kluch)
    return {
        'salt': base64.b64encode(sol).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'ciphertext': base64.b64encode(shifr.encrypt(nonce, master_key, None)).decode('utf-8')
    }


def decrypt_master_key(encrypted, password):
    sol = base64.b64decode(encrypted['salt'])
    nonce = base64.b64decode(encrypted['nonce'])
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=sol, iterations=600000)
    kluch = kdf.derive(password.encode())
    shifr = AESGCM(kluch)
    return shifr.decrypt(nonce, base64.b64decode(encrypted['ciphertext']), None)



class E2EEMasterKey:
    def __init__(self, master_key, salt=None):
        self.master_key = master_key
        self.identity_key = master_key[:32]
        self.encryption_key = master_key[32:48]
        self.derivation_key = master_key[48:64]
        self._derive_x25519_keypair()
        self._derive_ed25519_keypair()

    def _derive_x25519_keypair(self):
        zerno = hmac.new(b'static_keypair', self.identity_key, hashlib.sha256).digest()
        self.private_key = x25519.X25519PrivateKey.from_private_bytes(zerno[:32])
        self.public_key = self.private_key.public_key()

    def _derive_ed25519_keypair(self):
        zerno = hmac.new(self.derivation_key, b'ed25519_signing_v1', hashlib.sha256).digest()
        self.signing_private_key = Ed25519PrivateKey.from_private_bytes(zerno)
        self.signing_public_key = self.signing_private_key.public_key()

    def get_public_key_bytes(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def get_signing_public_key_bytes(self):
        return self.signing_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def encrypt_file_key_for_recipient(self, file_key, recipient_pub_bytes):
        recipient_pub = x25519.X25519PublicKey.from_public_bytes(recipient_pub_bytes)
        sekret = self.private_key.exchange(recipient_pub)
        kluch_oborotki = hmac.new(sekret, b'file_key_encryption_v1', hashlib.sha256).digest()
        nonce = os.urandom(12)
        shifr = AESGCM(kluch_oborotki)
        return base64.b64encode(nonce + shifr.encrypt(nonce, file_key, None)).decode('utf-8')

    def decrypt_file_key_from_sender(self, encrypted_blob_b64, sender_pub_bytes):
        sender_pub = x25519.X25519PublicKey.from_public_bytes(sender_pub_bytes)
        sekret = self.private_key.exchange(sender_pub)
        kluch_oborotki = hmac.new(sekret, b'file_key_encryption_v1', hashlib.sha256).digest()
        raw = base64.b64decode(encrypted_blob_b64)
        nonce, shifrovano = raw[:12], raw[12:]
        return AESGCM(kluch_oborotki).decrypt(nonce, shifrovano, None)


class E2EEContactManager:
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
        otvet = self.api.network_manager.send_sync_request('get_public_key', {
            'contact_login': contact_login
        })
        return self.process_key_response(contact_login, otvet)

    def process_key_response(self, contact_login, response):
        if not response or not response.get('success'):
            return None

        x_bytes, ed_bytes, new_format = self._parse_key_bundle(response.get('public_key', ''))
        if x_bytes is None:
            return None

        if new_format and ed_bytes:
            if not self._verify_ed25519_signature(x_bytes, ed_bytes, response.get('signature', '')):
                print(f"SECURITY: Ed25519 signature invalid for '{contact_login}' — key rejected")
                return None

        self.contact_keys[contact_login] = x_bytes
        self._tofu_check(contact_login, x_bytes, ed_bytes)
        return x_bytes

    def publish_own_key(self):
        moy_x = self.own_public_key
        moy_ed = self.master_key.get_signing_public_key_bytes()
        podpis = self.master_key.signing_private_key.sign(moy_x)
        bundle = json.dumps({
            'x25519': base64.b64encode(moy_x).decode(),
            'ed25519': base64.b64encode(moy_ed).decode()
        })
        self.api.network_manager.send_sync_request('publish_public_key', {
            'public_key': bundle,
            'signature': base64.b64encode(podpis).decode()
        })

    def _parse_key_bundle(self, pub_raw):
        if not pub_raw:
            return None, None, False
        if pub_raw.strip().startswith('{'):
            bundle = json.loads(pub_raw)
            if isinstance(bundle, dict) and 'x25519' in bundle and 'ed25519' in bundle:
                x_bytes = base64.b64decode(bundle['x25519'])
                ed_bytes = base64.b64decode(bundle['ed25519'])
                if len(x_bytes) == 32 and len(ed_bytes) == 32:
                    return x_bytes, ed_bytes, True
            return None, None, False
        # старый формат — просто base64 X25519
        raw = base64.b64decode(pub_raw)
        if len(raw) == 32:
            return raw, None, False
        return None, None, False

    def _verify_ed25519_signature(self, x_bytes, ed_bytes, sig_b64):
        try:
            podpis = base64.b64decode(sig_b64)
            pub = Ed25519PublicKey.from_public_bytes(ed_bytes)
            pub.verify(podpis, x_bytes)
            return True
        except (InvalidSignature, Exception):
            return False

    def _tofu_check(self, contact_login, x_bytes, ed_bytes):
        hranilishe = self._load_trust_store()
        kluch_b64 = base64.b64encode(x_bytes).decode()
        ed_b64 = base64.b64encode(ed_bytes).decode() if ed_bytes else None

        if contact_login not in hranilishe:
            hranilishe[contact_login] = {
                'x25519': kluch_b64,
                'ed25519': ed_b64,
                'first_seen': time.time(),
                'last_seen': time.time()
            }
            self._save_trust_store(hranilishe)
            return

        zapis = hranilishe[contact_login]
        if zapis['x25519'] != kluch_b64:
            staryy = zapis['x25519']
            hranilishe[contact_login] = {
                'x25519': kluch_b64,
                'ed25519': ed_b64,
                'first_seen': zapis.get('first_seen', time.time()),
                'last_seen': time.time()
            }
            self._save_trust_store(hranilishe)
            raise KeyChangedError(contact_login, staryy, kluch_b64, x_bytes)

        hranilishe[contact_login]['last_seen'] = time.time()
        if ed_b64 and not zapis.get('ed25519'):
            hranilishe[contact_login]['ed25519'] = ed_b64
        self._save_trust_store(hranilishe)

    def _get_trust_store_path(self):
        from utils import DATA_PATH
        login = getattr(self.api.network_manager, 'user_login', None) or 'unknown'
        trust_dir = DATA_PATH / 'key_trust'
        trust_dir.mkdir(parents=True, exist_ok=True)
        clean_login = ''.join(c for c in login if c.isalnum() or c in '-_')[:64]
        return trust_dir / f'{clean_login}.json'

    def _load_trust_store(self):
        path = self._get_trust_store_path()
        if not path.exists():
            return {}
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    def _save_trust_store(self, hranilishe):
        path = self._get_trust_store_path()
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(hranilishe, f, ensure_ascii=False, indent=2)


class E2EEMessageHandler:
    def __init__(self, master_key, contact_manager):
        self.master_key = master_key
        self.contact_manager = contact_manager

    def encrypt_message(self, plaintext, receiver_login):
        pub_poluchatelya = self.contact_manager.get_contact_public_key(receiver_login)
        if not pub_poluchatelya:
            raise Exception(f"Нет публичного ключа для {receiver_login}")

        pub_obj = x25519.X25519PublicKey.from_public_bytes(pub_poluchatelya)
        sekret = self.master_key.private_key.exchange(pub_obj)
        kluch_soobsh = hmac.new(sekret, b'message_key', hashlib.sha256).digest()
        nonce = os.urandom(12)
        moy_pub = self.contact_manager.get_own_public_key()
        shifrovano = AESGCM(kluch_soobsh).encrypt(nonce, plaintext.encode(), moy_pub)

        kluch_podpisi = hmac.new(sekret, b'signing', hashlib.sha256).digest()
        podpis = hmac.new(kluch_podpisi, shifrovano + nonce + moy_pub, hashlib.sha256).digest()

        return {
            'ciphertext': base64.b64encode(shifrovano).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'ephemeral_public': base64.b64encode(moy_pub).decode(),
            'signature': base64.b64encode(podpis).decode()
        }

    def decrypt_message(self, encrypted_data, contact_login):
        shifrovano = base64.b64decode(encrypted_data['ciphertext'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        pub_otp = base64.b64decode(encrypted_data['ephemeral_public'])
        podpis = base64.b64decode(encrypted_data['signature'])
        moy_pub = self.contact_manager.get_own_public_key()

        if pub_otp == moy_pub:
            pub_sobesedn = self.contact_manager.get_contact_public_key(contact_login)
            if not pub_sobesedn:
                raise Exception("Нет ключа собеседника для расшифровки своего сообщения")
            pub_obj = x25519.X25519PublicKey.from_public_bytes(pub_sobesedn)
        else:
            izvestnyy_pub = self.contact_manager.get_contact_public_key(contact_login)
            if izvestnyy_pub and pub_otp != izvestnyy_pub:
                return "[Ошибка: Неверная подпись]"
            pub_obj = x25519.X25519PublicKey.from_public_bytes(pub_otp)

        sekret = self.master_key.private_key.exchange(pub_obj)
        kluch_podpisi = hmac.new(sekret, b'signing', hashlib.sha256).digest()
        ozhid_podpis = hmac.new(kluch_podpisi, shifrovano + nonce + pub_otp, hashlib.sha256).digest()

        if not hmac.compare_digest(podpis, ozhid_podpis):
            return "[Ошибка: Неверная подпись]"

        kluch_soobsh = hmac.new(sekret, b'message_key', hashlib.sha256).digest()
        return AESGCM(kluch_soobsh).decrypt(nonce, shifrovano, pub_otp).decode('utf-8')
