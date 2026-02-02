import socket
import json
import hashlib
import uuid
import base64
import os


class Contact:
    def __init__(self, login, username, display_name=None):
        self.login = login
        self.username = username
        self.display_name = display_name or username

    def get_display_name(self):
        return self.display_name


def solevaya():
    return base64.b64encode(os.urandom(16)).decode('utf-8')[:16]


def hesir_parol(parol, sol=None):
    if sol is None:
        sol = solevaya()

    parol_s_sol = parol + sol
    hes = hashlib.sha256(parol_s_sol.encode()).hexdigest()

    return f"{hes}:{sol}"


def proverka_parol(parol, hranimiy_hesh):
    if not hranimiy_hesh or ':' not in hranimiy_hesh:
        stariy_hesh = hashlib.sha256(parol.encode()).hexdigest()
        return stariy_hesh == hranimiy_hesh

    chasti = hranimiy_hesh.split(':')
    if len(chasti) != 2:
        return False

    hranimiy_hesh, sol = chasti
    noviy_hesh = hashlib.sha256((parol + sol).encode()).hexdigest()

    return noviy_hesh == hranimiy_hesh


def izmenit_parol(parol, stariy_hesh):
    if hashlib.sha256(parol.encode()).hexdigest() == stariy_hesh:
        return hesir_parol(parol)
    return None


class SocketClient:

    def __init__(self, host='5.35.80.248', port=5000):
        self.host = host
        self.port = port
        self.soket = None
        self.soedineno = False

    def soedinenie(self):
        self.soket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.soket.connect((self.host, self.port))
        self.soedineno = True
        return True

    def razsoedinenie(self):
        if self.soket:
            self.soket.close()
            self.soket = None
            self.soedineno = False

    def otpravka(self, punkt, dannie):
        if not self.soedineno:
            if not self.soedinenie():
                return {'success': False, 'error': 'ошибка подключения'}

        zapros = {
            'endpoint': punkt,
            'data': dannie
        }

        zapros_json = json.dumps(zapros)
        self.soket.send(zapros_json.encode('utf-8'))

        otvet_dannie = b""
        while True:
            chank = self.soket.recv(4096)
            if not chank:
                break
            otvet_dannie += chank
            try:
                otvet = json.loads(otvet_dannie.decode('utf-8'))
                return otvet
            except:
                continue

        return {'success': False, 'error': 'пустой ответ'}


class MessengerAPI:

    def __init__(self, host='5.35.80.248', port=5000):
        self.klient = SocketClient(host, port)

    def registraciya(self, login, parol, username):
        parol_heshirovanniy = hesir_parol(parol)
        return self.klient.otpravka('register', {
            'login': login,
            'password': parol_heshirovanniy,
            'username': username
        })

    def vhod(self, login, parol):
        return self.klient.otpravka('login', {
            'login': login,
            'password': parol
        })

    def info(self, token, id_user):
        return self.klient.otpravka('info', {
            'user_token': token,
            'user_id': id_user
        })

    def otpravit_soobschenie(self, token, id_user, poluchatel_login, text):
        return self.klient.otpravka('send_message', {
            'user_token': token,
            'user_id': id_user,
            'receiver_login': poluchatel_login,
            'text': text
        })

    def poluchit_soobscheniya(self, token, id_user, drugoi_user_login):
        return self.klient.otpravka('get_messages', {
            'user_token': token,
            'user_id': id_user,
            'other_user_login': drugoi_user_login
        })

    def obnovit_profil(self, token, id_user, username=None, avatar=None, parol=None):
        dannie = {
            'user_token': token,
            'user_id': id_user
        }

        if username:
            dannie['username'] = username
        if avatar:
            dannie['avatar'] = avatar
        if parol:
            dannie['password'] = hesir_parol(parol)

        return self.klient.otpravka('update_profile', dannie)

    def dobavit_kontakt(self, token, id_user, kontakt_login):
        return self.klient.otpravka('add_contact', {
            'user_token': token,
            'user_id': id_user,
            'contact_login': kontakt_login
        })

    def poluchit_kontakti(self, token, id_user):
        return self.klient.otpravka('get_contacts', {
            'user_token': token,
            'user_id': id_user
        })

    def poluchit_avatar(self, token, id_user, kontakt_login):
        return self.klient.otpravka('get_avatar', {
            'user_token': token,
            'user_id': id_user,
            'contact_login': kontakt_login
        })

    def sohranit_nastroyki_kontakta(self, token, id_user, kontakt_login, imya_dlya_otobrajeniya):
        return self.klient.otpravka('save_contact_settings', {
            'user_token': token,
            'user_id': id_user,
            'contact_login': kontakt_login,
            'display_name': imya_dlya_otobrajeniya
        })

    def poluchit_nastroyki_kontakta(self, token, id_user):
        return self.klient.otpravka('get_contact_settings', {
            'user_token': token,
            'user_id': id_user
        })

    def udalit_kontakt(self, token, id_user, kontakt_login):
        return self.klient.otpravka('remove_contact', {
            'user_token': token,
            'user_id': id_user,
            'contact_login': kontakt_login
        })

    def razsoedinenie(self):
        self.klient.razsoedinenie()


messenger_api = MessengerAPI(host='5.35.80.248', port=5000)


def make_server_request(endpoint, data=None, method='POST'):
    if data is None:
        data = {}

    sootvetstvie = {
        'login': 'login',
        'register': 'register',
        'info': 'info',
        'send_message': 'send_message',
        'get_messages': 'get_messages',
        'update_profile': 'update_profile',
        'add_contact': 'add_contact',
        'get_contacts': 'get_contacts',
        'get_avatar': 'get_avatar',
        'save_contact_settings': 'save_contact_settings',
        'get_contact_settings': 'get_contact_settings',
        'remove_contact': 'remove_contact'
    }

    noviy_punkt = sootvetstvie.get(endpoint)

    if noviy_punkt == 'info':
        return messenger_api.info(
            token=data.get('user_token'),
            id_user=data.get('user_id')
        )
    elif noviy_punkt == 'send_message':
        return messenger_api.otpravit_soobschenie(
            token=data.get('user_token'),
            id_user=data.get('user_id'),
            poluchatel_login=data.get('receiver_login'),
            text=data.get('text')
        )
    elif noviy_punkt == 'get_messages':
        return messenger_api.poluchit_soobscheniya(
            token=data.get('user_token'),
            id_user=data.get('user_id'),
            drugoi_user_login=data.get('other_user_login')
        )
    elif noviy_punkt == 'update_profile':
        return messenger_api.obnovit_profil(
            token=data.get('user_token'),
            id_user=data.get('user_id'),
            username=data.get('username'),
            avatar=data.get('avatar'),
            parol=data.get('password')
        )
    elif noviy_punkt == 'add_contact':
        return messenger_api.dobavit_kontakt(
            token=data.get('user_token'),
            id_user=data.get('user_id'),
            kontakt_login=data.get('contact_login')
        )
    elif noviy_punkt == 'get_contacts':
        return messenger_api.poluchit_kontakti(
            token=data.get('user_token'),
            id_user=data.get('user_id')
        )
    elif noviy_punkt == 'get_avatar':
        return messenger_api.poluchit_avatar(
            token=data.get('user_token'),
            id_user=data.get('user_id'),
            kontakt_login=data.get('contact_login')
        )
    elif noviy_punkt == 'save_contact_settings':
        return messenger_api.sohranit_nastroyki_kontakta(
            token=data.get('user_token'),
            id_user=data.get('user_id'),
            kontakt_login=data.get('contact_login'),
            imya_dlya_otobrajeniya=data.get('display_name')
        )
    elif noviy_punkt == 'get_contact_settings':
        return messenger_api.poluchit_nastroyki_kontakta(
            token=data.get('user_token'),
            id_user=data.get('user_id')
        )
    elif noviy_punkt == 'remove_contact':
        return messenger_api.udalit_kontakt(
            token=data.get('user_token'),
            id_user=data.get('user_id'),
            kontakt_login=data.get('contact_login')
        )
    elif noviy_punkt == 'login':
        return messenger_api.vhod(
            login=data.get('login'),
            parol=data.get('password')
        )
    elif noviy_punkt == 'register':
        return messenger_api.registraciya(
            login=data.get('login'),
            parol=data.get('password'),
            username=data.get('username')
        )

    return {'success': False, 'error': f'неизвестный пункт: {endpoint}'}