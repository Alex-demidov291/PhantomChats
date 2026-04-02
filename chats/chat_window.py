from pathlib import Path
import sys
import os
import json
import time
import shutil
import mimetypes
from datetime import datetime, timedelta

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEngineSettings
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QFileDialog
from PyQt6.QtCore import QUrl, QTimer, QObject, pyqtSlot, Qt
from PyQt6.QtWebChannel import QWebChannel
from PyQt6.QtGui import QPixmap
from PyQt6.QtCore import QByteArray, QBuffer

from utils import BASE_PATH
from network import make_server_request_async, messenger_api, Contact
from network.crypto import KeyChangedError
import markdown
import base64
import html
import bleach


class Bridge(QObject):
    def __init__(self, chat_window):
        super().__init__()
        self.chat_window = chat_window

    @pyqtSlot()
    def loadUserData(self):
        self.chat_window.load_user_data()

    @pyqtSlot(str)
    def loadMessages(self, contact_login):
        self.chat_window.load_messages(contact_login)

    @pyqtSlot(str, str)
    def sendMessage(self, receiver_login, text):
        self.chat_window.send_message(receiver_login, text)

    @pyqtSlot(str)
    def attachFile(self, params_json):
        self.chat_window.attach_file(params_json)

    @pyqtSlot(int, str)
    def downloadFile(self, file_id, file_info_json):
        self.chat_window.download_file(file_id, json.loads(file_info_json))

    @pyqtSlot(str)
    def addContact(self, login):
        self.chat_window.add_contact(login)

    @pyqtSlot(str)
    def deleteChat(self, contact_login):
        self.chat_window.delete_chat(contact_login)

    @pyqtSlot(str, str)
    def renameContact(self, contact_login, new_name):
        self.chat_window.rename_contact(contact_login, new_name)

    @pyqtSlot()
    def showSettings(self):
        self.chat_window.show_settings()

    @pyqtSlot(str, str)
    def saveFullscreenImage(self, image_data, file_name):
        self.chat_window.save_fullscreen_image(image_data, file_name)


class MessageCache:
    def __init__(self, user_id):
        self.user_id = user_id
        from utils import DATA_PATH
        self.cache_dir = DATA_PATH / 'chats_save' / str(user_id)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_contact_file(self, contact_user_id):
        return self.cache_dir / f"{contact_user_id}.json"

    def load_messages(self, contact_user_id):
        fayl = self._get_contact_file(contact_user_id)
        if not fayl.exists():
            return []
        try:
            with open(fayl, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('messages', [])
        except (json.JSONDecodeError, OSError):
            return []

    def save_messages(self, contact_user_id, messages):
        fayl = self._get_contact_file(contact_user_id)
        data = {
            'contact_user_id': contact_user_id,
            'messages': messages,
            'last_message_id': messages[-1]['id'] if messages else 0,
            'updated_at': time.time()
        }
        with open(fayl, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def append_messages(self, contact_user_id, novye):
        if not novye:
            return []
        tekushchie = self.load_messages(contact_user_id)
        est_ids = {msg['id'] for msg in tekushchie}
        dobavit = [msg for msg in novye if msg['id'] not in est_ids]
        if not dobavit:
            return []
        tekushchie.extend(dobavit)
        tekushchie.sort(key=lambda x: x['id'])
        self.save_messages(contact_user_id, tekushchie)
        return dobavit

    def get_last_message_id(self, contact_user_id):
        fayl = self._get_contact_file(contact_user_id)
        if not fayl.exists():
            return 0
        try:
            with open(fayl, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('last_message_id', 0)
        except (json.JSONDecodeError, OSError):
            return 0

    def clear_cache(self):
        shutil.rmtree(self.cache_dir, ignore_errors=True)

    def save_contact_settings_cache(self, nastroyki):
        fayl = self.cache_dir / "contact_settings.json"
        try:
            with open(fayl, 'w', encoding='utf-8') as f:
                json.dump(nastroyki, f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    def load_contact_settings_cache(self):
        fayl = self.cache_dir / "contact_settings.json"
        if fayl.exists():
            try:
                with open(fayl, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return {}


class ChatWindow(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.cur_contact = None
        self.contacts = {}
        self.contact_avatars = {}
        self.script_dir = Path(BASE_PATH)
        self.page_loaded = False
        self.e2ee_ready = False
        self.pending_contact_load = None
        self.settings_retry_count = 0

        self.avatar_timer = QTimer()
        self.avatar_timer.timeout.connect(self.check_avatar_updates)
        self.avatar_timer.setInterval(60000)

        self.msg_cache = MessageCache(main_window.user_id)
        self.sync_timer = QTimer()
        self.sync_timer.timeout.connect(self.sync_all_contacts)
        self.sync_timer.setInterval(60000)
        self.contacts_need_update = False

        self.init_ui()
        self.load_contacts()
        self.setup_msg_listener()
        self.avatar_timer.start()
        self.sync_timer.start()

    def showEvent(self, event):
        super().showEvent(event)
        if self.page_loaded:
            self._update_contacts_js()
            if self.cur_contact:
                self.load_messages(self.cur_contact.login)
            self.sync_all_contacts()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.web_view = QWebEngineView()
        self.web_view.setStyleSheet("border: none; background: #ffffff;")
        self.web_view.loadFinished.connect(self.on_page_loaded)
        self.web_view.setZoomFactor(0.8)

        ws = self.web_view.settings()
        ws.setAttribute(QWebEngineSettings.WebAttribute.ScrollAnimatorEnabled, False)

        self.channel = QWebChannel(self.web_view.page())
        self.bridge = Bridge(self)
        self.channel.registerObject("qt", self.bridge)
        self.web_view.page().setWebChannel(self.channel)
        self.web_view.page().setBackgroundColor(Qt.GlobalColor.white)

        html_path = self.script_dir / "chats" / "messages.html"
        if html_path.exists():
            self.web_view.setUrl(QUrl.fromLocalFile(str(html_path.absolute())))
        else:
            self.web_view.setHtml("""
                <!DOCTYPE html><html>
                <head><meta charset="UTF-8"><title>Ошибка</title></head>
                <body style="font-family: Arial; padding: 20px;">
                    <h2>Файл messages.html не найден</h2>
                </body></html>
            """)
        layout.addWidget(self.web_view)

    def on_page_loaded(self, ok):
        if ok:
            self.page_loaded = True
            self.load_user_data()
            if self.contacts_need_update:
                self._update_contacts_js()
            if self.cur_contact:
                self.load_messages(self.cur_contact.login)
            self.sync_all_contacts()

    def load_user_data(self):
        if not self.page_loaded:
            return
        self.web_view.page().runJavaScript(f'setCurrentUser("{self.main_window.current_user}");')

    def fetch_contact_pubkey(self, contact):
        if not messenger_api.e2ee_contact_manager:
            return
        kluch = messenger_api.e2ee_contact_manager.get_contact_public_key(contact.login)
        if kluch:
            contact.public_key = kluch

    def _prefetch_key_then(self, contact, callback):
        if not messenger_api.e2ee_contact_manager:
            callback()
            return

        if contact.login in messenger_api.e2ee_contact_manager.contact_keys:
            contact.public_key = messenger_api.e2ee_contact_manager.contact_keys[contact.login]
            callback()
            return

        def handle_key_otvet(otvet):
            if otvet and otvet.get('success'):
                try:
                    kluch = messenger_api.e2ee_contact_manager.process_key_response(contact.login, otvet)
                    if kluch:
                        contact.public_key = kluch
                except KeyChangedError as e:
                    contact.public_key = e.new_key_bytes
                    safe_login = html.escape(contact.login).replace('"', '\\"')
                    self.web_view.page().runJavaScript(
                        f'showToast("⚠ Ключ {safe_login} изменился. Проверьте безопасность.", true);'
                    )
            callback()

        make_server_request_async('get_public_key', {
            'contact_login': contact.login,
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'session_token': self.main_window.session_token
        }, handle_key_otvet)

    def _process_e2ee_msg(self, msg, contact_login):
        if 'decrypted_text' in msg:
            return

        tekst = msg.get('message_text', '')
        if not tekst or not isinstance(tekst, str):
            return
        if not tekst.strip().startswith('{'):
            return

        data = json.loads(tekst)
        if not isinstance(data, dict) or data.get('type') != 'e2ee':
            return

        if not messenger_api.e2ee_message_handler:
            msg['message_text'] = '[E2EE не инициализирован]'
            return

        try:
            msg['message_text'] = messenger_api.e2ee_message_handler.decrypt_message(
                data['data'], contact_login)
        except Exception:
            msg['message_text'] = '[Ошибка расшифровки]'

    def _decrypt_file_bytes(self, raw_bytes, file_info, sender_login=None):
        if not file_info or not file_info.get('is_encrypted'):
            return raw_bytes
        encrypted_key = file_info.get('encrypted_key')
        nonce_file = file_info.get('nonce_file')
        if not encrypted_key or not nonce_file or not messenger_api.e2ee_master_key:
            return None
        try:
            nonce_bytes = base64.b64decode(nonce_file)
            return messenger_api.decrypt_file_data(raw_bytes, nonce_bytes, encrypted_key,
                                                   sender_login=sender_login)
        except Exception:
            return None

    def _ensure_sender_key_cached(self, sender_login):
        if not sender_login or not messenger_api.e2ee_contact_manager:
            return
        if sender_login in messenger_api.e2ee_contact_manager.contact_keys:
            return
        if sender_login == self.main_window.current_user:
            return
        kontakt = self.contacts.get(sender_login)
        if kontakt and kontakt.public_key:
            messenger_api.e2ee_contact_manager.contact_keys[sender_login] = kontakt.public_key

    def load_messages(self, contact_login):
        self.pending_contact_load = contact_login
        if not self.page_loaded:
            return
        kontakt = self.contacts.get(contact_login)
        if not kontakt:
            make_server_request_async('get_user_info', {
                'user_token': self.main_window.user_token,
                'user_id': self.main_window.user_id,
                'target_login': contact_login,
                'session_token': self.main_window.session_token
            }, lambda otvet: self._handle_user_info_response(contact_login, otvet))
            return
        self._load_messages_after_contact(kontakt)

    def _handle_user_info_response(self, contact_login, otvet):
        if self.pending_contact_load != contact_login:
            return
        if otvet and otvet.get('success'):
            u = otvet.get('user')
            novyy = Contact(login=u['login'], username=u['username'],
                            user_id=u['user_id'], avatar_version=u.get('avatar_version', 0))
            sushchestvuyushchiy = next(
                (c for c in self.contacts.values() if c.user_id == novyy.user_id), None)
            kontakt = sushchestvuyushchiy if sushchestvuyushchiy else novyy
            if not sushchestvuyushchiy:
                self.contacts[contact_login] = kontakt
            self.load_contact_avatar(kontakt)
            if messenger_api.e2ee_contact_manager:
                self.fetch_contact_pubkey(kontakt)
            self._load_messages_after_contact(kontakt)
        else:
            oshibka = otvet.get('error', 'Контакт не найден') if otvet else 'Ошибка соединения'
            self.web_view.page().runJavaScript(f'showToast("{oshibka}", true);')

    def _load_messages_after_contact(self, contact):
        if self.pending_contact_load != contact.login:
            return
        self.cur_contact = contact
        if messenger_api.e2ee_contact_manager:
            self._prefetch_key_then(contact, lambda: self._render_messages(contact))
        else:
            self._render_messages(contact)

    def _render_messages(self, contact):
        if self.pending_contact_load != contact.login:
            return

        aktualnyy = self.contacts.get(contact.login, contact)
        self.cur_contact = aktualnyy

        soobshenia = self.msg_cache.load_messages(aktualnyy.user_id)
        obrabotannyye = []
        for msg in soobshenia:
            msg = dict(msg)
            login_dlya_decrypt = (msg['receiver_login']
                                  if msg['sender_login'] == self.main_window.current_user
                                  else msg['sender_login'])
            self._process_e2ee_msg(msg, login_dlya_decrypt)
            obrabotannyye.append(self.prepare_msg_for_display(msg))

        self.web_view.page().runJavaScript(f'setMessages({json.dumps(obrabotannyye)});')
        self.ensure_msg_previews(aktualnyy.user_id, soobshenia)
        self.sync_contact_msgs(aktualnyy)

    def send_message(self, receiver_login, text):
        if not receiver_login or not text:
            return

        def handle_send_otvet(otvet):
            if otvet and otvet.get('success'):
                otpravlennoe = otvet.get('message')
                if otpravlennoe:
                    otpravlennoe['decrypted_text'] = text
                    kontakt = self.contacts.get(receiver_login)
                    if kontakt:
                        self.msg_cache.append_messages(kontakt.user_id, [otpravlennoe])
                    self.web_view.page().runJavaScript(
                        f'appendMessage({json.dumps(self.prepare_msg_for_display(otpravlennoe))});')
                    self.web_view.page().runJavaScript(
                        'document.getElementById("messageInput").value = "";')
                    if kontakt:
                        self.ensure_msg_previews(kontakt.user_id, [otpravlennoe])
            else:
                oshibka = otvet.get('error', 'Неизвестная ошибка') if otvet else 'Ошибка соединения'
                safe_error = html.escape(oshibka).replace('"', '\\"').replace("'", "\\'")
                self.web_view.page().runJavaScript(f'showToast("Ошибка: {safe_error}", true);')

        try:
            handle_send_otvet(messenger_api.send_message(
                token=self.main_window.user_token,
                user_id=self.main_window.user_id,
                receiver_login=receiver_login,
                text=text,
                file_id=None
            ))
        except KeyChangedError:
            safe_login = html.escape(receiver_login).replace('"', '\\"')
            self.web_view.page().runJavaScript(
                f'showToast("Ключ {safe_login} изменился. Проверьте безопасность.", true);')
            handle_send_otvet(messenger_api.send_message(
                token=self.main_window.user_token,
                user_id=self.main_window.user_id,
                receiver_login=receiver_login,
                text=text,
                file_id=None
            ))

    def attach_file(self, params_json):
        if not self.cur_contact:
            self.web_view.page().runJavaScript('showToast("Сначала выберите контакт", true);')
            return

        params = json.loads(params_json)
        tekst_vvoda = params.get('text', '')
        tolko_kartinka = params.get('isImageOnly', False)

        if tolko_kartinka:
            filtr = "Изображения (*.jpg *.jpeg *.png *.gif *.bmp)"
        else:
            filtr = ("Все файлы (*);;Изображения (*.jpg *.jpeg *.png *.gif *.bmp *.webp);;"
                     "Документы (*.pdf *.doc *.docx *.txt *.xls *.xlsx *.ppt *.pptx)")

        put_fayla, _ = QFileDialog.getOpenFileName(self, "Выбрать файл", "", filtr)
        if not put_fayla:
            return

        if os.path.getsize(put_fayla) > 10 * 1024 * 1024:
            self.web_view.page().runJavaScript('showToast("Файл слишком большой (максимум 10MB)", true);')
            return

        imya_fayla = os.path.basename(put_fayla)
        tip_fayla, _ = mimetypes.guess_type(put_fayla)
        if not tip_fayla:
            tip_fayla = "application/octet-stream"

        self.web_view.page().runJavaScript('showProgress(0);')
        with open(put_fayla, 'rb') as f:
            dannyye = f.read()

        def handle_upload_otvet(otvet):
            self.web_view.page().runJavaScript('showProgress(100);')
            if otvet and otvet.get('success'):
                self._send_msg_with_file(otvet.get('file_id'), tekst_vvoda,
                                         imya_fayla, tip_fayla, tolko_kartinka)
            else:
                oshibka = otvet.get('error', 'Неизвестная ошибка') if otvet else 'Ошибка соединения'
                safe_error = html.escape(oshibka).replace('"', '\\"').replace("'", "\\'")
                self.web_view.page().runJavaScript(f'showToast("Ошибка: {safe_error}", true);')

        payload = {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'file_name': imya_fayla,
            'file_type': tip_fayla,
            'is_image_only': tolko_kartinka,
            'session_token': self.main_window.session_token
        }

        login_poluchatelya = self.cur_contact.login
        pub_poluchatelya = (messenger_api.e2ee_contact_manager.contact_keys.get(login_poluchatelya)
                            if messenger_api.e2ee_master_key and messenger_api.e2ee_contact_manager
                            else None)

        if pub_poluchatelya:
            enc = messenger_api.encrypt_file_data(dannyye, None, receiver_login=login_poluchatelya)
            payload['file_data'] = enc['ciphertext']
            payload['encrypted_key'] = enc['encrypted_key']
            payload['nonce_file'] = enc['nonce_file']
            payload['is_encrypted'] = 1
        else:
            payload['file_data'] = base64.b64encode(dannyye).decode('utf-8')

        make_server_request_async('upload_file', payload, handle_upload_otvet)

    def _send_msg_with_file(self, file_id, text, file_name, file_type, is_image_only):
        polnyy_tekst = text if text.strip() else ""

        def handle_send_otvet(otvet):
            if otvet and otvet.get('success'):
                otpravlennoe = otvet.get('message')
                if otpravlennoe:
                    otpravlennoe['decrypted_text'] = polnyy_tekst
                    self.msg_cache.append_messages(self.cur_contact.user_id, [otpravlennoe])
                    self.web_view.page().runJavaScript(
                        f'appendMessage({json.dumps(self.prepare_msg_for_display(otpravlennoe))});')
                    self.web_view.page().runJavaScript(
                        'document.getElementById("messageInput").value = "";')
                    self.ensure_msg_previews(self.cur_contact.user_id, [otpravlennoe])
            else:
                oshibka = otvet.get('error', 'Неизвестная ошибка') if otvet else 'Ошибка соединения'
                safe_error = html.escape(oshibka).replace('"', '\\"').replace("'", "\\'")
                self.web_view.page().runJavaScript(f'showToast("Ошибка: {safe_error}", true);')

        handle_send_otvet(messenger_api.send_message(
            token=self.main_window.user_token,
            user_id=self.main_window.user_id,
            receiver_login=self.cur_contact.login,
            text=polnyy_tekst,
            file_id=file_id
        ))

    def download_file(self, file_id, file_info):
        if messenger_api.file_cache and messenger_api.file_cache.has_file(file_id):
            dannyye = messenger_api.file_cache.get_file_data(file_id)
            if dannyye:
                self.save_file_dialog(file_info['name'], dannyye)
                return

        self.web_view.page().runJavaScript('showProgress(0);')

        def handle_file_otvet(otvet):
            self.web_view.page().runJavaScript('showProgress(100);')
            if otvet and otvet.get('success'):
                raw = base64.b64decode(otvet.get('file_data'))
                dannyye = self._decrypt_file_bytes(raw, file_info,
                                                   sender_login=file_info.get('sender_login'))
                if dannyye is None:
                    self.web_view.page().runJavaScript('showToast("Ошибка расшифровки файла", true);')
                    return
                self.save_file_dialog(file_info['name'], dannyye)
                if messenger_api.file_cache:
                    messenger_api.file_cache.save_file(
                        file_id, file_info['name'], file_info['type'], len(dannyye), dannyye, None)
            else:
                oshibka = otvet.get('error', 'Неизвестная ошибка') if otvet else 'Ошибка соединения'
                safe_error = html.escape(oshibka).replace('"', '\\"').replace("'", "\\'")
                self.web_view.page().runJavaScript(
                    f'showToast("Не удалось загрузить файл: {safe_error}", true);')

        make_server_request_async('get_file', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'file_id': file_id,
            'include_data': True,
            'include_thumbnail': True,
            'session_token': self.main_window.session_token
        }, handle_file_otvet)

    def save_file_dialog(self, file_name, dannyye):
        from PyQt6.QtCore import QCoreApplication
        self.main_window.activateWindow()
        self.main_window.raise_()
        QCoreApplication.processEvents()

        suffix = Path(file_name).suffix.lstrip('.')
        filtr = (f"{suffix.upper()} файлы (*.{suffix});;Все файлы (*)"
                 if suffix else "Все файлы (*)")

        put_sohraneniya, _ = QFileDialog.getSaveFileName(
            self.main_window, "Сохранить файл", file_name, filtr)
        if put_sohraneniya:
            with open(put_sohraneniya, 'wb') as f:
                f.write(dannyye)
            self.web_view.page().runJavaScript('showToast("Файл сохранен");')
        else:
            self.web_view.page().runJavaScript('showToast("Сохранение отменено");')

    def save_fullscreen_image(self, image_data, file_name):
        from PyQt6.QtCore import QCoreApplication
        if image_data.startswith('data:'):
            image_data = image_data.split(',', 1)[1]
        bayty = base64.b64decode(image_data)
        self.main_window.activateWindow()
        self.main_window.raise_()
        QCoreApplication.processEvents()
        put_sohraneniya, _ = QFileDialog.getSaveFileName(
            self.main_window, "Сохранить изображение", file_name,
            "Изображения (*.jpg *.png *.gif);;Все файлы (*)")
        if put_sohraneniya:
            with open(put_sohraneniya, 'wb') as f:
                f.write(bayty)
            self.web_view.page().runJavaScript('showToast("Изображение сохранено");')

    def add_contact(self, contact_login):
        if not contact_login:
            self.web_view.page().runJavaScript('showToast("Введите логин пользователя!", true);')
            return
        if contact_login == self.main_window.current_user:
            self.web_view.page().runJavaScript('showToast("Нельзя добавить самого себя!", true);')
            return
        if contact_login in self.contacts:
            self.web_view.page().runJavaScript('showToast("Этот пользователь уже в контактах!", true);')
            return
        make_server_request_async('add_contact', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'contact_login': contact_login,
            'session_token': self.main_window.session_token
        }, lambda otvet: self._handle_add_contact_response(contact_login, otvet))

    def _handle_add_contact_response(self, contact_login, otvet):
        if otvet and otvet.get('success'):
            make_server_request_async('get_user_info', {
                'user_token': self.main_window.user_token,
                'user_id': self.main_window.user_id,
                'target_login': contact_login,
                'session_token': self.main_window.session_token
            }, lambda resp: self._handle_add_contact_info(contact_login, resp))
        else:
            oshibka = otvet.get('error', 'Неизвестная ошибка') if otvet else 'Ошибка соединения'
            safe_error = html.escape(oshibka).replace('"', '\\"').replace("'", "\\'")
            self.web_view.page().runJavaScript(f'showToast("Ошибка: {safe_error}", true);')

    def _handle_add_contact_info(self, contact_login, otvet):
        if otvet and otvet.get('success'):
            u = otvet.get('user')
            if u:
                novyy = Contact(login=u['login'], username=u['username'],
                                user_id=u['user_id'], avatar_version=u.get('avatar_version', 0))
                self.contacts[contact_login] = novyy
                self.load_contact_avatar(novyy)
                if messenger_api.e2ee_contact_manager:
                    self.fetch_contact_pubkey(novyy)
                self._update_contacts_js()
                self.web_view.page().runJavaScript('showToast("Контакт добавлен!");')
                self.load_contact_settings()
        else:
            self.web_view.page().runJavaScript('showToast("Пользователь не найден!", true);')

    def delete_chat(self, contact_login):
        make_server_request_async('remove_contact', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'contact_login': contact_login,
            'session_token': self.main_window.session_token
        }, lambda otvet: self._handle_remove_contact_response(contact_login, otvet))

    def _handle_remove_contact_response(self, contact_login, otvet):
        if otvet and otvet.get('success'):
            self.contacts.pop(contact_login, None)
            self.contact_avatars.pop(contact_login, None)
            self._update_contacts_js()
            if self.cur_contact and self.cur_contact.login == contact_login:
                self.cur_contact = None
                self.web_view.page().runJavaScript('showWelcomeScreen();')
            self.web_view.page().runJavaScript('showToast("Чат удален!");')

    def rename_contact(self, contact_login, new_name):
        if not new_name:
            return
        if len(new_name) > 64:
            self.web_view.page().runJavaScript('showToast("Имя не может быть длиннее 64 символов", true);')
            return
        make_server_request_async('save_contact_settings', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'contact_login': contact_login,
            'display_name': new_name,
            'session_token': self.main_window.session_token
        }, lambda otvet: self._handle_rename_contact_response(contact_login, new_name, otvet))

    def _handle_rename_contact_response(self, contact_login, new_name, otvet):
        if otvet and otvet.get('success') and contact_login in self.contacts:
            self.contacts[contact_login].display_name = new_name
            self._update_contacts_js()
            self._save_settings_cache()
            if self.cur_contact and self.cur_contact.login == contact_login:
                self.cur_contact.display_name = new_name
                safe_name = html.escape(new_name).replace('"', '\\"').replace("'", "\\'")
                self.web_view.page().runJavaScript(
                    f'document.getElementById("chatName").textContent = "{safe_name}";')
            self.web_view.page().runJavaScript('showToast("Контакт переименован!");')

    def show_settings(self):
        self.main_window.show_settings_window()

    def setup_msg_listener(self):
        messenger_api.network_manager.message_received.connect(self.on_msg_received)
        messenger_api.network_manager.avatar_updated.connect(self.on_avatar_updated)

    def on_msg_received(self, message_data):
        login_kontakta = (message_data['receiver_login']
                          if message_data['sender_login'] == self.main_window.current_user
                          else message_data['sender_login'])
        kontakt = self.contacts.get(login_kontakta)
        if not kontakt:
            return

        kopiya = dict(message_data)
        self._process_e2ee_msg(kopiya, login_kontakta)
        self.msg_cache.append_messages(kontakt.user_id, [message_data])

        if self.cur_contact and self.cur_contact.user_id == kontakt.user_id:
            self.web_view.page().runJavaScript(
                f'appendMessage({json.dumps(self.prepare_msg_for_display(kopiya))});')
            self.ensure_msg_previews(kontakt.user_id, [message_data])

    def on_avatar_updated(self, data):
        for kontakt in self.contacts.values():
            if kontakt.user_id == data.get('user_id'):
                kontakt.avatar_version = data.get('new_version')
                self.load_contact_avatar(kontakt, force_download=True)
                break

    def check_avatar_updates(self):
        nuzhno_proverit = [c for c in self.contacts.values() if c.needs_avatar_check()]
        if not nuzhno_proverit:
            return
        make_server_request_async('get_avatar_versions', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'user_ids': [c.user_id for c in nuzhno_proverit],
            'session_token': self.main_window.session_token
        }, lambda otvet: self._handle_avatar_versions_response(nuzhno_proverit, otvet))

    def _handle_avatar_versions_response(self, nuzhno_proverit, otvet):
        if otvet and otvet.get('success'):
            versii = otvet.get('versions', {})
            for kontakt in nuzhno_proverit:
                servernaya_versiya = versii.get(kontakt.user_id, 0)
                if servernaya_versiya != kontakt.avatar_version:
                    kontakt.avatar_version = servernaya_versiya
                    self.load_contact_avatar(kontakt, force_download=True)
                kontakt.update_avatar_check_time()

    def load_contact_avatars(self):
        for kontakt in self.contacts.values():
            self.load_contact_avatar(kontakt)

    def load_contact_avatar(self, contact, force_download=False):
        if (messenger_api.network_manager.has_avatar_cached(contact.user_id, contact.avatar_version)
                and not force_download):
            avatar_dannyye = messenger_api.network_manager.get_avatar_from_cache(
                contact.user_id, contact.avatar_version)
            if avatar_dannyye:
                pixmap = QPixmap()
                pixmap.loadFromData(avatar_dannyye)
                self.contact_avatars[contact.login] = pixmap
                self._update_avatar_in_js(contact.login)
                return

        def handle_avatar_otvet(otvet):
            if otvet and otvet.get('success') and otvet.get('avatar'):
                avatar_bayty = base64.b64decode(otvet['avatar'])
                messenger_api.network_manager.save_avatar_to_cache(
                    contact.user_id, contact.avatar_version, avatar_bayty)
                if contact.avatar_version > 0:
                    messenger_api.network_manager.remove_old_avatar(
                        contact.user_id, contact.avatar_version - 1)
                pixmap = QPixmap()
                pixmap.loadFromData(avatar_bayty)
                self.contact_avatars[contact.login] = pixmap
                self._update_avatar_in_js(contact.login)

        make_server_request_async('get_avatar', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'target_user_id': contact.user_id,
            'session_token': self.main_window.session_token
        }, handle_avatar_otvet)

    def load_contacts(self):
        make_server_request_async('get_contacts', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'session_token': self.main_window.session_token
        }, self._handle_contacts_response)

    def _handle_contacts_response(self, otvet):
        if otvet and otvet.get('success'):
            self.contacts = {}
            for d in otvet['contacts']:
                kontakt = Contact(login=d['login'], username=d['username'],
                                  user_id=d['user_id'], avatar_version=d.get('avatar_version', 0))
                kontakt.update_avatar_check_time()
                self.contacts[d['login']] = kontakt
            self._load_cached_settings()
            self._update_contacts_js()
            self.load_contact_avatars()
            self.sync_all_contacts()
            self.load_user_data()
            self.preload_all_imgs()
            QTimer.singleShot(400, self.load_contact_settings)

    def sync_all_contacts(self):
        for kontakt in self.contacts.values():
            self.sync_contact_msgs(kontakt)
        self.preload_all_imgs()

    def sync_contact_msgs(self, contact):
        last_id = self.msg_cache.get_last_message_id(contact.user_id)
        make_server_request_async('get_messages_since', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'contact_login': contact.login,
            'since_id': last_id,
            'session_token': self.main_window.session_token
        }, lambda otvet: self._handle_messages_since_response(contact, otvet))

    def _handle_messages_since_response(self, contact, otvet):
        if not otvet or not otvet.get('success'):
            return
        novyye = otvet.get('messages', [])
        if not novyye:
            return
        dobavlennyye = self.msg_cache.append_messages(contact.user_id, novyye)
        if not dobavlennyye:
            return
        if self.cur_contact and self.cur_contact.user_id == contact.user_id:
            for msg in dobavlennyye:
                kopiya = dict(msg)
                otpravitel = kopiya.get('sender_login')
                login_dlya_decrypt = (kopiya.get('receiver_login')
                                      if otpravitel == self.main_window.current_user
                                      else otpravitel)
                self._process_e2ee_msg(kopiya, login_dlya_decrypt)
                self.web_view.page().runJavaScript(
                    f'appendMessage({json.dumps(self.prepare_msg_for_display(kopiya))});')
            self.ensure_msg_previews(contact.user_id, dobavlennyye)

    def preload_all_imgs(self):
        for kontakt in self.contacts.values():
            for msg in self.msg_cache.load_messages(kontakt.user_id):
                if msg.get('has_file') and msg.get('file_info') and msg['file_info'].get('is_image_only'):
                    file_id = msg['file_info']['id']
                    if not messenger_api.file_cache or not messenger_api.file_cache.has_file(file_id):
                        self._load_file_preview_bg(file_id, msg['id'], kontakt.user_id)

    def ensure_msg_previews(self, contact_user_id, soobshenia):
        for msg in soobshenia:
            if msg.get('has_file') and msg.get('file_info') and msg['file_info'].get('is_image_only'):
                file_id = msg['file_info']['id']
                if not messenger_api.file_cache or not messenger_api.file_cache.has_file(file_id):
                    self._load_file_preview(file_id, msg['id'], contact_user_id)

    def _load_file_preview(self, file_id, message_id, contact_user_id):
        def handle_otvet(otvet):
            if not otvet or not otvet.get('success'):
                return
            raw = base64.b64decode(otvet.get('file_data'))
            for msg in self.msg_cache.load_messages(contact_user_id):
                if msg.get('id') == message_id and msg.get('file_info'):
                    otpravitel = msg.get('sender_login')
                    self._ensure_sender_key_cached(otpravitel)
                    dannyye = self._decrypt_file_bytes(raw, msg.get('file_info'),
                                                       sender_login=otpravitel)
                    if dannyye is None:
                        break
                    prevyu = self._gen_thumbnail(dannyye)
                    if messenger_api.file_cache:
                        messenger_api.file_cache.save_file(
                            file_id,
                            msg['file_info'].get('name', 'unknown'),
                            msg['file_info'].get('type', 'application/octet-stream'),
                            msg['file_info'].get('size', 0),
                            dannyye, prevyu)
                    if prevyu:
                        prevyu_b64 = base64.b64encode(prevyu).decode('utf-8')
                        self.web_view.page().runJavaScript(
                            f'updateMessageThumbnail({message_id}, "{prevyu_b64}");')
                    break

        make_server_request_async('get_file', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'file_id': file_id,
            'include_data': True,
            'session_token': self.main_window.session_token
        }, handle_otvet)

    def _load_file_preview_bg(self, file_id, message_id, contact_user_id):
        def handle_otvet(otvet):
            if not otvet or not otvet.get('success'):
                return
            raw = base64.b64decode(otvet.get('file_data'))
            for msg in self.msg_cache.load_messages(contact_user_id):
                if msg.get('id') == message_id and msg.get('file_info'):
                    otpravitel = msg.get('sender_login')
                    self._ensure_sender_key_cached(otpravitel)
                    dannyye = self._decrypt_file_bytes(raw, msg.get('file_info'),
                                                       sender_login=otpravitel)
                    if dannyye is None:
                        break
                    prevyu = self._gen_thumbnail(dannyye)
                    if messenger_api.file_cache:
                        messenger_api.file_cache.save_file(
                            file_id,
                            msg['file_info'].get('name', 'unknown'),
                            msg['file_info'].get('type', 'application/octet-stream'),
                            msg['file_info'].get('size', 0),
                            dannyye, prevyu)
                    break

        make_server_request_async('get_file', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'file_id': file_id,
            'include_data': True,
            'session_token': self.main_window.session_token
        }, handle_otvet)

    def load_contact_settings(self):
        make_server_request_async('get_contact_settings', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'session_token': self.main_window.session_token
        }, self._handle_settings_response)

    def _handle_settings_response(self, otvet):
        if otvet and otvet.get('success'):
            nastroyki = otvet.get('settings', {})
            obnovleno = False
            for login, setting in nastroyki.items():
                if login in self.contacts:
                    imya = setting.get('display_name')
                    if imya and self.contacts[login].display_name != imya:
                        self.contacts[login].display_name = imya
                        obnovleno = True
            if obnovleno:
                self._update_contacts_js()
                self._save_settings_cache()
                if self.cur_contact and self.cur_contact.login in nastroyki:
                    novoe_imya = nastroyki[self.cur_contact.login].get('display_name')
                    if novoe_imya:
                        self.cur_contact.display_name = novoe_imya
                        safe_name = html.escape(novoe_imya).replace('"', '\\"').replace("'", "\\'")
                        self.web_view.page().runJavaScript(
                            f'document.getElementById("chatName").textContent = "{safe_name}";')
            self._save_settings_cache()
            self.settings_retry_count = 0
        else:
            if self.settings_retry_count < 3:
                self.settings_retry_count += 1
                QTimer.singleShot(1500, self.load_contact_settings)

    def _load_cached_settings(self):
        kesh = self.msg_cache.load_contact_settings_cache()
        obnovleno = False
        for login, imya in kesh.items():
            if login in self.contacts and self.contacts[login].display_name != imya:
                self.contacts[login].display_name = imya
                obnovleno = True
        if obnovleno:
            self._update_contacts_js()
            if self.cur_contact and self.cur_contact.login in kesh:
                self.web_view.page().runJavaScript(
                    f'document.getElementById("chatName").textContent = '
                    f'"{html.escape(kesh[self.cur_contact.login])}";')

    def _save_settings_cache(self):
        self.msg_cache.save_contact_settings_cache({
            login: c.display_name
            for login, c in self.contacts.items()
            if c.display_name and c.display_name != c.username
        })

    def prepare_msg_for_display(self, msg):
        kopiya = dict(msg)
        tekst = kopiya.get('decrypted_text', kopiya.get('message_text', ''))
        if tekst:
            html_tekst = markdown.markdown(tekst, extensions=['nl2br', 'tables'])
            allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'a', 'ul', 'ol', 'li',
                            'blockquote', 'code', 'pre', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6']
            allowed_attrs = {'a': ['href', 'title']}
            kopiya['message_text'] = bleach.clean(
                html_tekst, tags=allowed_tags, attributes=allowed_attrs,
                strip=True, protocols=['http', 'https', 'mailto'])
        else:
            kopiya['message_text'] = ''

        if kopiya.get('has_file') and kopiya.get('file_info'):
            fi = kopiya['file_info']
            fi['sender_login'] = kopiya.get('sender_login', '')
            fi.setdefault('is_encrypted', False)
            fi.setdefault('encrypted_key', None)
            fi.setdefault('nonce_file', None)
            kopiya['is_image_only'] = fi.get('is_image_only', False)
            if fi.get('is_image_only') and fi['type'].startswith('image/'):
                if messenger_api.file_cache:
                    dannyye = messenger_api.file_cache.get_file_data(fi['id'])
                    if dannyye:
                        prevyu = messenger_api.file_cache.get_thumbnail_data(fi['id'])
                        if prevyu:
                            fi['thumbnail'] = base64.b64encode(prevyu).decode('utf-8')
            else:
                fi['icon'] = self.get_file_icon(fi['type'])
                fi['size_kb'] = round(fi['size'] / 1024, 1)

        dt = datetime.fromisoformat(kopiya.get('timestamp', '').replace('Z', '+00:00'))
        kopiya['display_time'] = (dt + timedelta(hours=3)).strftime("%d.%m %H:%M")
        return kopiya

    def get_file_icon(self, file_type):
        if file_type.startswith('image/'):
            return '🖼️'
        if file_type.startswith('video/'):
            return '🎬'
        if file_type.startswith('audio/'):
            return '🎵'
        if file_type == 'application/pdf':
            return '📕'
        if 'word' in file_type or 'document' in file_type:
            return '📘'
        if 'excel' in file_type or 'sheet' in file_type:
            return '📗'
        if 'presentation' in file_type or 'powerpoint' in file_type:
            return '📙'
        if 'text' in file_type:
            return '📄'
        return '📎'

    def _gen_thumbnail(self, image_data, max_size=(400, 400)):
        from PIL import Image
        import io
        img = Image.open(io.BytesIO(image_data))
        img.thumbnail(max_size, Image.Resampling.LANCZOS)
        if img.mode in ('RGBA', 'LA', 'P'):
            img = img.convert('RGB')
        vyvod = io.BytesIO()
        img.save(vyvod, format='JPEG', quality=70, optimize=True)
        return vyvod.getvalue()

    def _update_contacts_js(self):
        if not self.page_loaded:
            self.contacts_need_update = True
            return
        spisok = [
            {
                'login': c.login,
                'username': c.username,
                'display_name': html.escape(c.get_display_name()) if c.get_display_name() else c.login,
                'avatar': self._get_avatar_data(c.login)
            }
            for c in self.contacts.values()
        ]
        self.web_view.page().runJavaScript(f'setContacts({json.dumps(spisok)});')
        self.contacts_need_update = False

    def _update_avatar_in_js(self, login):
        if not self.page_loaded:
            return
        dannyye = self._get_avatar_data(login)
        if dannyye:
            self.web_view.page().runJavaScript(f'updateContactAvatar("{login}", "{dannyye}");')

    def _get_avatar_data(self, login):
        pixmap = self.contact_avatars.get(login)
        if pixmap and not pixmap.isNull():
            byte_array = QByteArray()
            buf = QBuffer(byte_array)
            buf.open(QBuffer.OpenModeFlag.WriteOnly)
            pixmap.save(buf, "PNG")
            return 'data:image/png;base64,' + byte_array.toBase64().data().decode()
        return self._get_default_avatar_data()

    def _get_default_avatar_data(self):
        default_path = self.script_dir / "images" / "default_avatar.jpg"
        pixmap = QPixmap(str(default_path)) if default_path.exists() else QPixmap(60, 60)
        if not default_path.exists():
            pixmap.fill(Qt.GlobalColor.gray)
        byte_array = QByteArray()
        buf = QBuffer(byte_array)
        buf.open(QBuffer.OpenModeFlag.WriteOnly)
        pixmap.save(buf, "PNG")
        return 'data:image/png;base64,' + byte_array.toBase64().data().decode()

    def closeEvent(self, event):
        self.avatar_timer.stop()
        self.sync_timer.stop()
        super().closeEvent(event)
