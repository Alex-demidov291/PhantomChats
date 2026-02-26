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
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QFileDialog
from PyQt6.QtCore import QUrl, QTimer, QObject, pyqtSlot, Qt
from PyQt6.QtWebChannel import QWebChannel
from PyQt6.QtGui import QPixmap
from PyQt6.QtCore import QByteArray, QBuffer

from network import make_server_request_async, messenger_api, Contact
import markdown
import base64
import html
import bleach


class Bridge(QObject):
    # -- мост для связи с html
    def __init__(self, chat_window):
        super().__init__()
        self.chat_window = chat_window

    @pyqtSlot()
    def loadUserData(self):
        # - загрузка данных юзера
        self.chat_window.load_user_data()

    @pyqtSlot(str)
    def loadMessages(self, contact_login):
        # - загрузка сообщения
        self.chat_window.load_messages(contact_login)

    @pyqtSlot(str, str)
    def sendMessage(self, receiver_login, text):
        # - отправка сообщение
        self.chat_window.send_message(receiver_login, text)

    @pyqtSlot(str)
    def attachFile(self, params_json):
        # - прикрепление файла
        self.chat_window.attach_file(params_json)

    @pyqtSlot(int, str)
    def downloadFile(self, file_id, file_info_json):
        file_info = json.loads(file_info_json)
        self.chat_window.download_file(file_id, file_info)

    @pyqtSlot(str)
    def addContact(self, login):
        # - добавление контакта
        self.chat_window.add_contact(login)

    @pyqtSlot(str)
    def deleteChat(self, contact_login):
        # - удаление чата
        self.chat_window.delete_chat(contact_login)

    @pyqtSlot(str, str)
    def renameContact(self, contact_login, new_name):
        # - переименование контакта
        self.chat_window.rename_contact(contact_login, new_name)

    @pyqtSlot()
    def showSettings(self):
        # - показ настроек
        self.chat_window.show_settings()

    @pyqtSlot(str, str)
    def saveFullscreenImage(self, image_data, file_name):
        # - сохрание картинки
        self.chat_window.save_fullscreen_image(image_data, file_name)


class MessageCache:
    #  -- кэш сообщений
    def __init__(self, user_id):
        self.user_id = user_id
        self.cache_dir = Path(f'chats_save/{user_id}')
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_contact_file(self, contact_login):
        return self.cache_dir / f"{contact_login}.json"

    def load_messages(self, contact_login):
        filepath = self._get_contact_file(contact_login)
        if not filepath.exists():
            return []
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('messages', [])

    def save_messages(self, contact_login, messages):
        filepath = self._get_contact_file(contact_login)
        data = {
            'contact_login': contact_login,
            'messages': messages,
            'last_message_id': messages[-1]['id'] if messages else 0,
            'updated_at': time.time()
        }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def append_messages(self, contact_login, new_messages):
        if not new_messages:
            return []
        current = self.load_messages(contact_login)
        existing_ids = {msg['id'] for msg in current}
        to_add = [msg for msg in new_messages if msg['id'] not in existing_ids]
        if not to_add:
            return []
        current.extend(to_add)
        current.sort(key=lambda x: x['id'])
        self.save_messages(contact_login, current)
        return to_add

    def get_last_message_id(self, contact_login):
        filepath = self._get_contact_file(contact_login)
        if not filepath.exists():
            return 0
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('last_message_id', 0)

    def clear_cache(self):
        shutil.rmtree(self.cache_dir, ignore_errors=True)


class ChatWindow(QWidget):
    # -- главное окно чата

    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.cur_contact = None
        self.contacts = {}
        self.contact_avatars = {}
        self.script_dir = Path(__file__).parent.parent
        self.page_loaded = False
        self.e2ee_ready = False

        self.avatar_timer = QTimer()
        self.avatar_timer.timeout.connect(self.check_avatar_updates)
        self.avatar_timer.setInterval(60000)

        self.msg_cache = MessageCache(main_window.user_id)

        self.sync_timer = QTimer()
        self.sync_timer.timeout.connect(self.sync_all_contacts)
        self.sync_timer.setInterval(60000)

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
        self.web_view.setStyleSheet("border: none; background: #f5f5f5;")
        self.web_view.loadFinished.connect(self.on_page_loaded)
        self.web_view.setZoomFactor(0.8)

        self.channel = QWebChannel(self.web_view.page())
        self.bridge = Bridge(self)
        self.channel.registerObject("qt", self.bridge)
        self.web_view.page().setWebChannel(self.channel)

        html_path = self.script_dir / "chats" / "messages.html"
        if html_path.exists():
            self.web_view.setUrl(QUrl.fromLocalFile(str(html_path.absolute())))
        else:
            self.web_view.setHtml("""
                <!DOCTYPE html>
                <html>
                <head><meta charset="UTF-8"><title>Ошибка</title></head>
                <body style="font-family: Arial; padding: 20px;">
                    <h2>Файл messages.html не найден</h2>
                </body>
                </html>
            """)

        layout.addWidget(self.web_view)

    def on_page_loaded(self, ok):
        if ok:
            self.page_loaded = True
            self.load_user_data()
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
        pub = messenger_api.e2ee_contact_manager.get_contact_public_key(contact.login)
        if pub:
            contact.public_key = pub

    def _process_e2ee_msg(self, msg, contact_login):
        if 'decrypted_text' in msg:
            return
        text = msg.get('message_text', '')
        if not text:
            return
        if isinstance(text, str):
            data = json.loads(text)
        else:
            data = text
        if isinstance(data, dict) and data.get('type') == 'e2ee':
            if messenger_api.e2ee_message_handler:
                decrypted = messenger_api.e2ee_message_handler.decrypt_message(
                    data['data'],
                    contact_login
                )
                msg['message_text'] = decrypted
            else:
                msg['message_text'] = '[Ошибка: E2EE не инициализирован]'

    def load_messages(self, contact_login):
        if not self.page_loaded:
            return
        contact = self.contacts.get(contact_login)
        if not contact:
            return
        self.cur_contact = contact

        if messenger_api.e2ee_contact_manager and not contact.public_key:
            self.fetch_contact_pubkey(contact)

        messages = self.msg_cache.load_messages(contact_login)
        processed = []
        for msg in messages:
            if msg['sender_login'] == self.main_window.current_user:
                login_for_decrypt = msg['receiver_login']
            else:
                login_for_decrypt = msg['sender_login']
            self._process_e2ee_msg(msg, login_for_decrypt)
            processed.append(self.prepare_msg_for_display(msg))

        self.web_view.page().runJavaScript(f'setMessages({json.dumps(processed)});')
        self.ensure_msg_previews(contact_login, messages)
        self.sync_contact_msgs(contact_login)

    def send_message(self, receiver_login, text):
        if not receiver_login or not text:
            return

        def handle_send_response(response):
            if response and response.get('success'):
                sent_message = response.get('message')
                if sent_message:
                    sent_message['decrypted_text'] = text
                    self.msg_cache.append_messages(receiver_login, [sent_message])
                    msg_display = self.prepare_msg_for_display(sent_message)
                    self.web_view.page().runJavaScript(f'appendMessage({json.dumps(msg_display)});')
                    self.web_view.page().runJavaScript('document.getElementById("messageInput").value = "";')
            else:
                error = response.get('error', 'Неизвестная ошибка') if response else 'Ошибка соединения'
                safe_error = html.escape(error).replace('"', '\\"').replace("'", "\\'")
                self.web_view.page().runJavaScript(f'showToast("Ошибка: {safe_error}", true);')

        response = messenger_api.send_message(
            token=self.main_window.user_token,
            user_id=self.main_window.user_id,
            receiver_login=receiver_login,
            text=text,
            file_id=None
        )
        handle_send_response(response)

    def attach_file(self, params_json):
        if not self.cur_contact:
            self.web_view.page().runJavaScript('showToast("Сначала выберите контакт", true);')
            return

        params = json.loads(params_json)
        text_from_input = params.get('text', '')
        is_image_only = params.get('isImageOnly', False)

        file_filter = "Все файлы (*)"
        if is_image_only:
            file_filter = "Изображения (*.jpg *.jpeg *.png *.gif *.bmp)"
        else:
            file_filter = ("Все файлы (*);;Изображения (*.jpg *.jpeg *.png *.gif *.bmp *.webp);;"
                           "Документы (*.pdf *.doc *.docx *.txt *.xls *.xlsx *.ppt *.pptx)")

        file_path, _ = QFileDialog.getOpenFileName(self, "Выбрать файл", "", file_filter)
        if not file_path:
            return

        file_size = os.path.getsize(file_path)
        if file_size > 10 * 1024 * 1024:
            self.web_view.page().runJavaScript('showToast("Файл слишком большой (максимум 10MB)", true);')
            return

        file_name = os.path.basename(file_path)
        file_type, _ = mimetypes.guess_type(file_path)
        if not file_type:
            file_type = "application/octet-stream"

        self.web_view.page().runJavaScript('showProgress(0);')

        with open(file_path, 'rb') as f:
            file_data = f.read()
        file_base64 = base64.b64encode(file_data).decode('utf-8')

        def handle_upload_response(response):
            self.web_view.page().runJavaScript('showProgress(100);')
            if response and response.get('success'):
                file_id = response.get('file_id')
                self._send_msg_with_file(file_id, text_from_input, file_name, file_type, is_image_only)
            else:
                error_msg = response.get('error', 'Неизвестная ошибка') if response else 'Ошибка соединения'
                safe_error = html.escape(error_msg).replace('"', '\\"').replace("'", "\\'")
                self.web_view.page().runJavaScript(f'showToast("Ошибка: {safe_error}", true);')

        make_server_request_async('upload_file', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'file_data': file_base64,
            'file_name': file_name,
            'file_type': file_type,
            'is_image_only': is_image_only,
            'session_token': self.main_window.session_token
        }, handle_upload_response)

    def _send_msg_with_file(self, file_id, text, file_name, file_type, is_image_only):
        full_text = text if text.strip() else ""

        def handle_send_response(response):
            if response and response.get('success'):
                sent_message = response.get('message')
                if sent_message:
                    sent_message['decrypted_text'] = full_text
                    self.msg_cache.append_messages(self.cur_contact.login, [sent_message])
                    msg_display = self.prepare_msg_for_display(sent_message)
                    self.web_view.page().runJavaScript(f'appendMessage({json.dumps(msg_display)});')
                    self.web_view.page().runJavaScript('document.getElementById("messageInput").value = "";')
                    self.ensure_msg_previews(self.cur_contact.login, [sent_message])
            else:
                error = response.get('error', 'Неизвестная ошибка') if response else 'Ошибка соединения'
                safe_error = html.escape(error).replace('"', '\\"').replace("'", "\\'")
                self.web_view.page().runJavaScript(f'showToast("Ошибка: {safe_error}", true);')

        response = messenger_api.send_message(
            token=self.main_window.user_token,
            user_id=self.main_window.user_id,
            receiver_login=self.cur_contact.login,
            text=full_text,
            file_id=file_id
        )
        handle_send_response(response)

    def download_file(self, file_id, file_info):
        if messenger_api.file_cache and messenger_api.file_cache.has_file(file_id):
            file_data = messenger_api.file_cache.get_file_data(file_id)
            if file_data:
                self.save_file_dialog(file_info['name'], file_data)
                return

        self.web_view.page().runJavaScript('showProgress(0);')

        def handle_file_response(response):
            self.web_view.page().runJavaScript('showProgress(100);')
            if response and response.get('success'):
                file_data = base64.b64decode(response.get('file_data'))
                self.save_file_dialog(file_info['name'], file_data)
                if messenger_api.file_cache:
                    messenger_api.file_cache.save_file(
                        file_id, file_info['name'], file_info['type'],
                        len(file_data), file_data, None
                    )
            else:
                error_msg = response.get('error', 'Неизвестная ошибка') if response else 'Ошибка соединения'
                safe_error = html.escape(error_msg).replace('"', '\\"').replace("'", "\\'")
                self.web_view.page().runJavaScript(f'showToast("Не удалось загрузить файл: {safe_error}", true);')

        make_server_request_async('get_file', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'file_id': file_id,
            'include_data': True,
            'include_thumbnail': True,
            'session_token': self.main_window.session_token
        }, handle_file_response)

    def save_file_dialog(self, file_name, file_data):
        main_window = self.main_window
        main_window.activateWindow()
        main_window.raise_()
        from PyQt6.QtCore import QCoreApplication
        QCoreApplication.processEvents()

        suffix = Path(file_name).suffix.lstrip('.')
        if suffix:
            filter_str = f"{suffix.upper()} файлы (*.{suffix});;Все файлы (*)"
        else:
            filter_str = "Все файлы (*)"

        save_path, _ = QFileDialog.getSaveFileName(
            main_window,
            "Сохранить файл",
            file_name,
            filter_str
        )

        if save_path:
            with open(save_path, 'wb') as f:
                f.write(file_data)
            self.web_view.page().runJavaScript('showToast("Файл сохранен");')
        else:
            self.web_view.page().runJavaScript('showToast("Сохранение отменено");')

    def save_fullscreen_image(self, image_data, file_name):
        if image_data.startswith('data:image'):
            import re
            image_data = re.sub('^data:image/.+;base64,', '', image_data)
        file_bytes = base64.b64decode(image_data)
        self.save_file_dialog(file_name, file_bytes)

    def _handle_add_contact_search(self, contact_login, response):
        if response and response.get('success'):
            users = response.get('users', [])
            username = contact_login
            user_id = None
            avatar_version = 0
            for user in users:
                if user['login'] == contact_login:
                    username = user['username']
                    user_id = user['user_id']
                    avatar_version = user.get('avatar_version', 0)
                    break

            new_contact = Contact(
                login=contact_login,
                username=username,
                user_id=user_id,
                avatar_version=avatar_version
            )
            new_contact.update_avatar_check_time()
            self.contacts[contact_login] = new_contact
            self.load_contact_avatar(new_contact)
            if messenger_api.e2ee_contact_manager:
                self.fetch_contact_pubkey(new_contact)
            self._update_contacts_js()
            self.web_view.page().runJavaScript('showToast("Контакт добавлен!");')

    def _handle_add_contact_response(self, contact_login, response):
        if response and response.get('success'):
            make_server_request_async('search_users', {
                'user_token': self.main_window.user_token,
                'user_id': self.main_window.user_id,
                'search_query': contact_login,
                'session_token': self.main_window.session_token
            }, lambda resp: self._handle_add_contact_search(contact_login, resp))
        else:
            error_msg = response.get('error', 'Неизвестная ошибка') if response else 'Ошибка соединения'
            safe_error = html.escape(error_msg).replace('"', '\\"').replace("'", "\\'")
            self.web_view.page().runJavaScript(f'showToast("Ошибка: {safe_error}", true);')

    def add_contact(self, contact_login):
        if not contact_login:
            self.web_view.page().runJavaScript('showToast("Введите логин пользователя!", true);')
            return
        if contact_login == self.main_window.current_user:
            self.web_view.page().runJavaScript('showToast("Нельзя добавить самого себя!", true);')
            return
        if contact_login in self.contacts:
            self.web_view.page().runJavaScript('showToast("Этот контакт уже добавлен!", true);')
            return

        make_server_request_async('add_contact', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'contact_login': contact_login,
            'session_token': self.main_window.session_token
        }, lambda resp: self._handle_add_contact_response(contact_login, resp))

    def _handle_remove_contact_response(self, contact_login, response):
        if response and response.get('success'):
            if contact_login in self.contacts:
                del self.contacts[contact_login]
            if contact_login in self.contact_avatars:
                del self.contact_avatars[contact_login]
            self._update_contacts_js()
            if self.cur_contact and self.cur_contact.login == contact_login:
                self.cur_contact = None
                self.web_view.page().runJavaScript('showWelcomeScreen();')
            self.web_view.page().runJavaScript('showToast("Чат удален!");')

    def delete_chat(self, contact_login):
        make_server_request_async('remove_contact', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'contact_login': contact_login,
            'session_token': self.main_window.session_token
        }, lambda resp: self._handle_remove_contact_response(contact_login, resp))

    def _handle_rename_contact_response(self, contact_login, new_name, response):
        if response and response.get('success'):
            if contact_login in self.contacts:
                self.contacts[contact_login].display_name = new_name
                self._update_contacts_js()

                if self.cur_contact and self.cur_contact.login == contact_login:
                    self.cur_contact.display_name = new_name
                    safe_name = html.escape(new_name).replace('"', '\\"').replace("'", "\\'")
                    self.web_view.page().runJavaScript(
                        f'document.getElementById("chatName").textContent = "{safe_name}";')

                self.web_view.page().runJavaScript('showToast("Контакт переименован!");')

    def rename_contact(self, contact_login, new_name):
        if not new_name:
            return

        make_server_request_async('save_contact_settings', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'contact_login': contact_login,
            'display_name': new_name,
            'session_token': self.main_window.session_token
        }, lambda resp: self._handle_rename_contact_response(contact_login, new_name, resp))

    def show_settings(self):
        self.main_window.show_settings_window()

    def setup_msg_listener(self):
        messenger_api.network_manager.message_received.connect(self.on_msg_received)
        messenger_api.network_manager.avatar_updated.connect(self.on_avatar_updated)

    def on_msg_received(self, message_data):
        if message_data['sender_login'] == self.main_window.current_user:
            contact_login = message_data['receiver_login']
        else:
            contact_login = message_data['sender_login']

        self._process_e2ee_msg(message_data, contact_login)
        self.msg_cache.append_messages(contact_login, [message_data])

        if self.cur_contact and self.cur_contact.login == contact_login:
            msg_display = self.prepare_msg_for_display(message_data)
            self.web_view.page().runJavaScript(f'appendMessage({json.dumps(msg_display)});')
            self.ensure_msg_previews(contact_login, [message_data])

    def on_avatar_updated(self, data):
        user_id = data.get('user_id')
        new_version = data.get('new_version')
        for contact in self.contacts.values():
            if contact.user_id == user_id:
                contact.avatar_version = new_version
                self.load_contact_avatar(contact, force_download=True)
                break

    def _handle_avatar_versions_response(self, need_check, response):
        if response and response.get('success'):
            versions = response.get('versions', {})
            for contact in need_check:
                server_version = versions.get(contact.user_id, 0)
                if server_version != contact.avatar_version:
                    contact.avatar_version = server_version
                    self.load_contact_avatar(contact, force_download=True)
                contact.update_avatar_check_time()

    def check_avatar_updates(self):
        if not self.contacts:
            return
        need_check = [c for c in self.contacts.values() if c.needs_avatar_check()]
        if not need_check:
            return

        user_ids = [c.user_id for c in need_check]

        make_server_request_async('get_avatar_versions', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'user_ids': user_ids,
            'session_token': self.main_window.session_token
        }, lambda resp: self._handle_avatar_versions_response(need_check, resp))

    def _handle_contacts_response(self, response):
        if response and response.get('success'):
            self.contacts = {}
            for contact_data in response['contacts']:
                contact = Contact(
                    login=contact_data['login'],
                    username=contact_data['username'],
                    user_id=contact_data['user_id'],
                    avatar_version=contact_data.get('avatar_version', 0)
                )
                contact.update_avatar_check_time()
                self.contacts[contact_data['login']] = contact

            self.load_contact_avatars()
            self.load_contact_settings()
            self.sync_all_contacts()
            self._update_contacts_js()
            self.load_user_data()
            self.preload_all_imgs()

    def load_contacts(self):
        make_server_request_async('get_contacts', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'session_token': self.main_window.session_token
        }, self._handle_contacts_response)

    def preload_all_imgs(self):
        for contact_login in self.contacts:
            messages = self.msg_cache.load_messages(contact_login)
            for msg in messages:
                if msg.get('has_file') and msg.get('file_info') and msg['file_info'].get('is_image_only'):
                    file_id = msg['file_info']['id']
                    if not messenger_api.file_cache or not messenger_api.file_cache.has_file(file_id):
                        self._load_file_preview_bg(file_id, msg['id'], contact_login)

    def _load_file_preview_bg(self, file_id, message_id, contact_login):
        def handle_response(response):
            if response and response.get('success'):
                file_data = base64.b64decode(response.get('file_data'))
                messages = self.msg_cache.load_messages(contact_login)
                for msg in messages:
                    if msg.get('id') == message_id and msg.get('file_info'):
                        thumbnail = self._gen_thumbnail(file_data)
                        if messenger_api.file_cache:
                            messenger_api.file_cache.save_file(
                                file_id,
                                msg['file_info'].get('name', 'unknown'),
                                msg['file_info'].get('type', 'application/octet-stream'),
                                msg['file_info'].get('size', 0),
                                file_data,
                                thumbnail
                            )
                        break

        make_server_request_async('get_file', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'file_id': file_id,
            'include_data': True,
            'session_token': self.main_window.session_token
        }, handle_response)

    def sync_all_contacts(self):
        for contact_login in self.contacts:
            self.sync_contact_msgs(contact_login)
        self.preload_all_imgs()


    def _handle_messages_since_response(self, contact_login, response):
        if response and response.get('success'):
            new_messages = response.get('messages', [])
            if new_messages:
                self.msg_cache.append_messages(contact_login, new_messages)

                if self.cur_contact and self.cur_contact.login == contact_login:
                    for msg in new_messages:
                        sender = msg.get('sender_login')
                        if sender == self.main_window.current_user:
                            login_for_decrypt = msg.get('receiver_login')
                        else:
                            login_for_decrypt = sender
                        self._process_e2ee_msg(msg, login_for_decrypt)
                        msg_display = self.prepare_msg_for_display(msg)
                        self.web_view.page().runJavaScript(f'appendMessage({json.dumps(msg_display)});')
                    self.ensure_msg_previews(contact_login, new_messages)

    def sync_contact_msgs(self, contact_login):
        last_id = self.msg_cache.get_last_message_id(contact_login)

        make_server_request_async('get_messages_since', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'contact_login': contact_login,
            'since_id': last_id,
            'session_token': self.main_window.session_token
        }, lambda resp: self._handle_messages_since_response(contact_login, resp))

    def load_contact_avatars(self):
        for contact in self.contacts.values():
            self.load_contact_avatar(contact)

    def load_contact_avatar(self, contact, force_download=False):
        if (messenger_api.network_manager.has_avatar_cached(contact.user_id, contact.avatar_version)
                and not force_download):
            avatar_data = messenger_api.network_manager.get_avatar_from_cache(
                contact.user_id, contact.avatar_version
            )
            if avatar_data:
                pixmap = QPixmap()
                pixmap.loadFromData(avatar_data)
                self.contact_avatars[contact.login] = pixmap
                self._update_avatar_in_js(contact.login)
                return

        def handle_avatar_response(response):
            if response and response.get('success'):
                avatar_data = response.get('avatar')
                if avatar_data:
                    avatar_bytes = base64.b64decode(avatar_data)
                    messenger_api.network_manager.save_avatar_to_cache(
                        contact.user_id, contact.avatar_version, avatar_bytes
                    )
                    if contact.avatar_version > 0:
                        messenger_api.network_manager.remove_old_avatar(
                            contact.user_id, contact.avatar_version - 1
                        )

                    pixmap = QPixmap()
                    pixmap.loadFromData(avatar_bytes)
                    self.contact_avatars[contact.login] = pixmap
                    self._update_avatar_in_js(contact.login)

        make_server_request_async('get_avatar', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'target_user_id': contact.user_id,
            'session_token': self.main_window.session_token
        }, handle_avatar_response)

    def _handle_settings_response(self, response):
        if response and response.get('success'):
            settings = response.get('settings', {})
            for contact_login, setting in settings.items():
                if contact_login in self.contacts:
                    display_name = setting.get('display_name')
                    if display_name:
                        self.contacts[contact_login].display_name = display_name
            self._update_contacts_js()

    def load_contact_settings(self):
        make_server_request_async('get_contact_settings', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'session_token': self.main_window.session_token
        }, self._handle_settings_response)

    def prepare_msg_for_display(self, msg):
        msg_copy = dict(msg)
        text = msg_copy.get('decrypted_text', msg_copy.get('message_text', ''))
        if text:
            escaped = html.escape(text)
            html_text = markdown.markdown(escaped, extensions=['nl2br', 'tables'])
            allowed_tags = [
                'p', 'br', 'strong', 'em', 'u', 'a', 'ul', 'ol', 'li',
                'blockquote', 'code', 'pre', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'
            ]
            allowed_attrs = {'a': ['href', 'title']}
            safe_html = bleach.clean(html_text, tags=allowed_tags, attributes=allowed_attrs)
            msg_copy['message_text'] = safe_html
        else:
            msg_copy['message_text'] = ''

        if msg_copy.get('has_file') and msg_copy.get('file_info'):
            file_info = msg_copy['file_info']
            msg_copy['is_image_only'] = file_info.get('is_image_only', False)
            if file_info.get('is_image_only') and file_info['type'].startswith('image/'):
                if messenger_api.file_cache:
                    file_data = messenger_api.file_cache.get_file_data(file_info['id'])
                    if file_data:
                        thumbnail = messenger_api.file_cache.get_thumbnail_data(file_info['id'])
                        if thumbnail:
                            file_info['thumbnail'] = base64.b64encode(thumbnail).decode('utf-8')
            else:
                file_info['icon'] = self.get_file_icon(file_info['type'])
                file_info['size_kb'] = round(file_info['size'] / 1024, 1)

        timestamp = msg_copy.get('timestamp', '')
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        dt = dt + timedelta(hours=3)
        msg_copy['display_time'] = dt.strftime("%d.%m %H:%M")

        return msg_copy

    def get_file_icon(self, file_type):
        if file_type.startswith('image/'):
            return '🖼️'
        elif file_type.startswith('video/'):
            return '🎬'
        elif file_type.startswith('audio/'):
            return '🎵'
        elif file_type == 'application/pdf':
            return '📕'
        elif 'word' in file_type or 'document' in file_type:
            return '📘'
        elif 'excel' in file_type or 'sheet' in file_type:
            return '📗'
        elif 'presentation' in file_type or 'powerpoint' in file_type:
            return '📙'
        elif 'text' in file_type:
            return '📄'
        else:
            return '📎'

    def _gen_thumbnail(self, image_data, max_size=(400, 400)):
        from PIL import Image
        import io
        img = Image.open(io.BytesIO(image_data))
        img.thumbnail(max_size, Image.Resampling.LANCZOS)
        if img.mode in ('RGBA', 'LA', 'P'):
            img = img.convert('RGB')
        output = io.BytesIO()
        img.save(output, format='JPEG', quality=70, optimize=True)
        return output.getvalue()

    def ensure_msg_previews(self, contact_login, messages):
        for msg in messages:
            if msg.get('has_file') and msg.get('file_info') and msg['file_info'].get('is_image_only'):
                file_id = msg['file_info']['id']
                if not messenger_api.file_cache or not messenger_api.file_cache.has_file(file_id):
                    self._load_file_preview(file_id, msg['id'], contact_login)

    def _load_file_preview(self, file_id, message_id, contact_login):
        def handle_response(response):
            if response and response.get('success'):
                file_data = base64.b64decode(response.get('file_data'))
                messages = self.msg_cache.load_messages(contact_login)
                for msg in messages:
                    if msg.get('id') == message_id and msg.get('file_info'):
                        thumbnail = self._gen_thumbnail(file_data)
                        if messenger_api.file_cache:
                            messenger_api.file_cache.save_file(
                                file_id,
                                msg['file_info'].get('name', 'unknown'),
                                msg['file_info'].get('type', 'application/octet-stream'),
                                msg['file_info'].get('size', 0),
                                file_data,
                                thumbnail
                            )
                        if thumbnail:
                            thumbnail_b64 = base64.b64encode(thumbnail).decode('utf-8')
                            self.web_view.page().runJavaScript(
                                f'updateMessageThumbnail({message_id}, "{thumbnail_b64}");')
                        break

        make_server_request_async('get_file', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'file_id': file_id,
            'include_data': True,
            'session_token': self.main_window.session_token
        }, handle_response)

    def _update_contacts_js(self):
        if not self.page_loaded:
            return
        contacts_list = []
        for contact in self.contacts.values():
            avatar_data = self._get_avatar_data(contact.login)
            safe_display_name = html.escape(contact.get_display_name()) if contact.get_display_name() else contact.login
            contacts_list.append({
                'login': contact.login,
                'username': contact.username,
                'display_name': safe_display_name,
                'avatar': avatar_data
            })
        self.web_view.page().runJavaScript(f'setContacts({json.dumps(contacts_list)});')

    def _update_avatar_in_js(self, login):
        if not self.page_loaded:
            return
        avatar_data = self._get_avatar_data(login)
        if avatar_data:
            self.web_view.page().runJavaScript(f'updateContactAvatar("{login}", "{avatar_data}");')

    def _get_avatar_data(self, login):
        pixmap = self.contact_avatars.get(login)
        if pixmap and not pixmap.isNull():
            byte_array = QByteArray()
            buffer = QBuffer(byte_array)
            buffer.open(QBuffer.OpenModeFlag.WriteOnly)
            pixmap.save(buffer, "PNG")
            return 'data:image/png;base64,' + byte_array.toBase64().data().decode()
        else:
            return self._get_default_avatar_data()

    def _get_default_avatar_data(self):
        default_path = self.script_dir / "images" / "default_avatar.jpg"
        if default_path.exists():
            pixmap = QPixmap(str(default_path))
        else:
            pixmap = QPixmap(60, 60)
            pixmap.fill(Qt.GlobalColor.gray)
        byte_array = QByteArray()
        buffer = QBuffer(byte_array)
        buffer.open(QBuffer.OpenModeFlag.WriteOnly)
        pixmap.save(buffer, "PNG")
        return 'data:image/png;base64,' + byte_array.toBase64().data().decode()

    def closeEvent(self, event):
        self.avatar_timer.stop()
        self.sync_timer.stop()
        super().closeEvent(event)