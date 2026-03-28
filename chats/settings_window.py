from PyQt6.QtWidgets import QWidget, QVBoxLayout
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEngineSettings
from PyQt6.QtWebChannel import QWebChannel
from PyQt6.QtCore import QObject, pyqtSlot, QUrl, Qt
import sys
import os
import base64
import json
import html
from pathlib import Path

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from styles import defult_ava, angle_alf, numbers
from network import make_server_request_async, messenger_api


class SettingsBridge(QObject):
    def __init__(self, settings_window):
        super().__init__()
        self.settings_window = settings_window

    @pyqtSlot()
    def loadUserData(self):
        self.settings_window.load_user_data()

    @pyqtSlot(str)
    def changeName(self, new_name):
        self.settings_window.change_name(new_name)

    @pyqtSlot(str, str)
    def changePassword(self, new_password, confirm_password):
        self.settings_window.change_password(new_password, confirm_password)

    @pyqtSlot()
    def changeAvatar(self):
        self.settings_window.change_avatar()

    @pyqtSlot()
    def showSessions(self):
        self.settings_window.show_sessions_dialog()

    @pyqtSlot()
    def showCleanup(self):
        self.settings_window.show_cleanup_dialog()

    @pyqtSlot(str)
    def logoutSelectedSession(self, session_id):
        self.settings_window.logout_selected_session(session_id)

    @pyqtSlot()
    def logoutAllSessions(self):
        self.settings_window.logout_all_sessions()

    @pyqtSlot(int)
    def saveCleanupSettings(self, interval):
        self.settings_window.save_cleanup_settings(interval)

    @pyqtSlot()
    def backToChat(self):
        self.settings_window.show_chat_window()

    @pyqtSlot()
    def logout(self):
        self.settings_window.logout()


class SettingsWindow(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.session_id = main_window.session_id
        self.user_id = main_window.user_id
        self.cur_ava_path = defult_ava
        self.bridge = SettingsBridge(self)
        self.init_ui()
        self.script_dir = Path(__file__).parent.parent

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.web_view = QWebEngineView()
        self.web_view.setStyleSheet("border: none; background: #ffffff;")

        ws = self.web_view.settings()
        ws.setAttribute(QWebEngineSettings.WebAttribute.ScrollAnimatorEnabled, False)

        self.channel = QWebChannel(self.web_view.page())
        self.channel.registerObject("backend", self.bridge)
        self.web_view.page().setWebChannel(self.channel)
        self.web_view.page().setBackgroundColor(Qt.GlobalColor.white)
        self.web_view.setZoomFactor(0.87)

        html_path = Path(__file__).parent / "settings_template.html"
        if html_path.exists():
            self.web_view.setUrl(QUrl.fromLocalFile(str(html_path.absolute())))
        else:
            self.web_view.setHtml(self.get_fallback_html(), QUrl("file://"))

        layout.addWidget(self.web_view)

    def get_fallback_html(self):
        return """
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"><title>Settings</title></head>
        <body style="font-family: Arial; padding: 20px;">
            <h2>Ошибка загрузки интерфейса</h2>
            <p>Файл settings_template.html не найден</p>
        </body>
        </html>
        """

    def load_user_data(self):
        default_avatar_path = self.script_dir / "images" / "default_avatar.jpg"
        if default_avatar_path.exists():
            with open(default_avatar_path, 'rb') as f:
                default_avatar_data = f.read()
                default_avatar_base64 = base64.b64encode(default_avatar_data).decode('utf-8')
                self.web_view.page().runJavaScript(f'setDefaultAvatarFromBase64("{default_avatar_base64}");')

        def handle_info_response(response):
            if response and response.get('success'):
                user_id = response.get('user_id')
                username = response.get('username', '')
                avatar_version = response.get('avatar_version', 0)

                self.web_view.page().runJavaScript(f'setUsername("{username}");')

                if messenger_api.network_manager.has_avatar_cached(user_id, avatar_version):
                    avatar_data = messenger_api.network_manager.get_avatar_from_cache(user_id, avatar_version)
                    if avatar_data:
                        avatar_base64 = base64.b64encode(avatar_data).decode('utf-8')
                        self.web_view.page().runJavaScript(f'updateAvatar("{avatar_base64}");')
                        return

                def handle_avatar_response(avatar_response):
                    if avatar_response and avatar_response.get('success'):
                        avatar_data = avatar_response.get('avatar')
                        if avatar_data:
                            avatar_bytes = base64.b64decode(avatar_data)
                            messenger_api.network_manager.save_avatar_to_cache(user_id, avatar_version, avatar_bytes)
                            self.web_view.page().runJavaScript(f'updateAvatar("{avatar_data}");')
                        else:
                            self.web_view.page().runJavaScript('showDefaultAvatar();')
                    else:
                        self.web_view.page().runJavaScript('showDefaultAvatar();')

                make_server_request_async('get_avatar', {
                    'session_id': self.session_id,
                    'user_id': self.user_id,
                    'target_user_id': user_id,
                }, handle_avatar_response)

        make_server_request_async('info', {
            'session_id': self.session_id,
            'user_id': self.user_id,
        }, handle_info_response)

    def change_name(self, new_name):
        if len(new_name) < 4 or len(new_name) > 20:
            self.web_view.page().runJavaScript(
                'showToast("Имя должно содержать минимум 4, максимум 20 символов!", true);')
            return

        def handle_change_name_response(response):
            if response and response.get('success'):
                self.main_window.username = new_name
                self.web_view.page().runJavaScript('showToast("Имя успешно изменено!");')
            else:
                error_msg = response.get('error', 'Неизвестная ошибка') if response else 'Ошибка соединения'
                safe_error = html.escape(error_msg).replace('"', '\\"').replace("'", "\\'")
                self.web_view.page().runJavaScript(f'showToast("Ошибка: {safe_error}", true);')

        make_server_request_async('update_profile', {
            'session_id': self.session_id,
            'user_id': self.user_id,
            'username': new_name,
        }, handle_change_name_response)

    def change_avatar(self):
        from PyQt6.QtWidgets import QFileDialog
        fname = QFileDialog.getOpenFileName(
            self, 'Выбрать аватар', '',
            'Изображения (*.jpg *.jpeg *.png *.gif *.bmp *.webp)')[0]
        if fname:
            with open(fname, 'rb') as f:
                image_data = f.read()
            if len(image_data) > 150 * 1024:
                self.web_view.page().runJavaScript('showToast("Изображение слишком большое (максимум 150KB)!", true);')
                return

            from PIL import Image
            import io
            img = Image.open(io.BytesIO(image_data))
            if img.width > 8000 or img.height > 5000:
                self.web_view.page().runJavaScript(
                    'showToast("Изображение слишком большое (максимум 8000x5000)!", true);')
                return

            avatar_base64 = base64.b64encode(image_data).decode('utf-8')

            def handle_change_avatar_response(response):
                if response and response.get('success'):
                    avatar_version = response.get('avatar_version', 0)
                    avatar_data = response.get('avatar')
                    if avatar_data:
                        avatar_bytes = base64.b64decode(avatar_data)
                        messenger_api.network_manager.save_avatar_to_cache(
                            self.user_id, avatar_version, avatar_bytes
                        )
                        if avatar_version > 0:
                            messenger_api.network_manager.remove_old_avatar(
                                self.user_id, avatar_version - 1
                            )
                        self.web_view.page().runJavaScript(f'updateAvatar("{avatar_data}");')
                    self.web_view.page().runJavaScript('showToast("Аватар успешно изменен!");')
                else:
                    error_msg = response.get('error', 'Неизвестная ошибка') if response else 'Ошибка соединения'
                    safe_error = html.escape(error_msg).replace('"', '\\"').replace("'", "\\'")
                    self.web_view.page().runJavaScript(f'showToast("Ошибка: {safe_error}", true);')

            make_server_request_async('update_profile', {
                'session_id': self.session_id,
                'user_id': self.user_id,
                'avatar': avatar_base64,
            }, handle_change_avatar_response)

    def change_password(self, new_password, confirm_password):
        if not new_password or not confirm_password:
            self.web_view.page().runJavaScript('showToast("Заполните все поля!", true);')
            return

        if new_password != confirm_password:
            self.web_view.page().runJavaScript('showToast("Пароли не совпадают!", true);')
            return

        if len(new_password) < 8 or len(new_password) > 25:
            self.web_view.page().runJavaScript(
                'showToast("Пароль должен содержать минимум 8, максимум 25 символов!", true);')
            return

        number_for_pass = False
        zagl_for_pass = False
        low_for_pass = False
        has_special = False

        for el in new_password:
            if el in numbers:
                number_for_pass = True
            elif el in angle_alf:
                low_for_pass = True
            elif el in angle_alf.upper():
                zagl_for_pass = True
            elif not el.isalnum():
                has_special = True

        if not (number_for_pass and zagl_for_pass and low_for_pass and has_special):
            self.web_view.page().runJavaScript(
                'showToast("Пароль должен содержать маленькие и заглавные английские буквы, цифры или спец символы", true);')
            return

        def handle_change_password_response(response):
            if response and response.get('success'):
                self.web_view.page().runJavaScript('clearPasswordFields();')
                self.web_view.page().runJavaScript(
                    'showToast("Пароль успешно изменен! Все остальные сессии завершены.");')
                self.web_view.page().runJavaScript('closeAllModals();')
            else:
                error_msg = response.get('error', 'Неизвестная ошибка') if response else 'Ошибка соединения'
                safe_error = html.escape(error_msg).replace('"', '\\"').replace("'", "\\'")
                self.web_view.page().runJavaScript(f'showToast("Ошибка: {safe_error}", true);')

        messenger_api.opaque_change_password_async(new_password, handle_change_password_response)

    def show_sessions_dialog(self):
        def handle_sessions_response(response):
            if response and response.get('success'):
                sessions = response.get('sessions', [])
                # sessions will contain the hashed session_id (full hash) and other fields
                # We need to pass them to JS
                sessions_json = json.dumps(sessions)
                self.web_view.page().runJavaScript(f'updateSessionsList({sessions_json}); openModal("sessionsModal");')
            else:
                error_msg = response.get('error', 'Неизвестная ошибка') if response else 'Ошибка соединения'
                safe_error = html.escape(error_msg).replace('"', '\\"').replace("'", "\\'")
                self.web_view.page().runJavaScript(f'showToast("Не удалось загрузить сессии: {safe_error}", true);')

        make_server_request_async('get_sessions', {
            'session_id': self.session_id,
            'user_id': self.user_id,
        }, handle_sessions_response)

    def logout_selected_session(self, session_id):
        def handle_logout_response(response):
            if response and response.get('success'):
                self.web_view.page().runJavaScript('showToast("Сессия завершена");')
                self.show_sessions_dialog()  # refresh list
            else:
                error_msg = response.get('error', 'Неизвестная ошибка') if response else 'Ошибка соединения'
                safe_error = html.escape(error_msg).replace('"', '\\"').replace("'", "\\'")
                self.web_view.page().runJavaScript(f'showToast("Не удалось завершить сессию: {safe_error}", true);')

        make_server_request_async('logout_session', {
            'session_id': self.session_id,
            'user_id': self.user_id,
            'target_session_id': session_id,
        }, handle_logout_response)

    def logout_all_sessions(self):
        def handle_logout_all_response(response):
            if response and response.get('success'):
                self.web_view.page().runJavaScript('showToast("Все другие сессии завершены");')
                self.show_sessions_dialog()
            else:
                error_msg = response.get('error', 'Неизвестная ошибка') if response else 'Ошибка соединения'
                safe_error = html.escape(error_msg).replace('"', '\\"').replace("'", "\\'")
                self.web_view.page().runJavaScript(f'showToast("Не удалось завершить сессии: {safe_error}", true);')

        make_server_request_async('logout_all_sessions', {
            'session_id': self.session_id,
            'user_id': self.user_id,
        }, handle_logout_all_response)

    def show_cleanup_dialog(self):
        def handle_interval_response(response):
            if response and response.get('success'):
                interval = response.get('cleanup_interval', 0)
                self.web_view.page().runJavaScript(f'setCleanupInterval({interval}); openModal("cleanupModal");')
            else:
                error_msg = response.get('error', 'Неизвестная ошибка') if response else 'Ошибка соединения'
                safe_error = html.escape(error_msg).replace('"', '\\"').replace("'", "\\'")
                self.web_view.page().runJavaScript(
                    f'showToast("Не удалось загрузить настройки очистки: {safe_error}", true);')

        make_server_request_async('get_cleanup_interval', {
            'session_id': self.session_id,
            'user_id': self.user_id,
        }, handle_interval_response)

    def save_cleanup_settings(self, interval):
        def handle_save_response(response):
            if response and response.get('success'):
                self.web_view.page().runJavaScript(
                    'showToast("Настройки очистки сохранены"); closeModal("cleanupModal");')
            else:
                error_msg = response.get('error', 'Неизвестная ошибка') if response else 'Ошибка соединения'
                safe_error = html.escape(error_msg).replace('"', '\\"').replace("'", "\\'")
                self.web_view.page().runJavaScript(f'showToast("Ошибка: {safe_error}", true);')

        make_server_request_async('set_cleanup_interval', {
            'session_id': self.session_id,
            'user_id': self.user_id,
            'interval': interval,
        }, handle_save_response)

    def show_chat_window(self):
        self.main_window.show_chat_window()

    def logout(self):
        self.main_window.logout()

    def closeEvent(self, event):
        if self.web_view:
            self.web_view.stop()
            self.web_view.setPage(None)
        super().closeEvent(event)
