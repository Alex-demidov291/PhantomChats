from pathlib import Path
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
                             QListWidget, QTextEdit, QTextBrowser, QLineEdit, QToolButton,
                             QMenu, QInputDialog, QMessageBox, QDialog, QListWidgetItem)
from PyQt6.QtGui import QIcon, QPixmap, QPainter, QPainterPath, QBrush, QColor, QPen, QTextOption
from PyQt6.QtCore import QSize, Qt, QUrl
from jinja2 import Template

from styles import (style_input_field, style_chat_list, style_message_area1, style_mesg,
                    style_round_btn, style_tool_button, style_menu, style_hi_label, defult_ava)
from network import make_server_request
from network import Contact
import markdown
import base64
import html


class SearchDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Поиск пользователей")
        self.setFixedSize(400, 500)

        layout = QVBoxLayout(self)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Введите имя или логин пользователя...")
        self.search_input.setStyleSheet(style_input_field)
        self.search_input.textChanged.connect(self.on_search_changed)

        self.results_list = QListWidget()
        self.results_list.setStyleSheet(style_chat_list)
        self.results_list.itemClicked.connect(self.on_user_selected)

        button_layout = QHBoxLayout()
        self.cancel_button = QPushButton("Отмена")
        self.cancel_button.clicked.connect(self.reject)
        self.cancel_button.setStyleSheet(style_round_btn)

        self.add_button = QPushButton("Добавить выбранного")
        self.add_button.clicked.connect(self.accept)
        self.add_button.setStyleSheet(style_round_btn)
        self.add_button.setEnabled(False)

        button_layout.addWidget(self.cancel_button)
        button_layout.addWidget(self.add_button)

        layout.addWidget(QLabel("Поиск пользователей:"))
        layout.addWidget(self.search_input)
        layout.addWidget(self.results_list)
        layout.addLayout(button_layout)

        self.selected_user = None

    def on_search_changed(self, text):
        if text.strip():
            self.parent().search_users(text.strip(), self)
        else:
            self.results_list.clear()

    def on_user_selected(self, item):
        self.selected_user = item.data(Qt.ItemDataRole.UserRole)
        self.add_button.setEnabled(bool(self.selected_user))

    def get_selected_user(self):
        return self.selected_user


class AutoResizeTextEdit(QTextEdit):
    def __init__(self, *args, max_lines=4, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_lines = max_lines
        self.textChanged.connect(self.adjustHeight)
        self.setWordWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
        self.setMinimumHeight(self.lineHeight())
        self.setMaximumHeight(self.lineHeight() * self.max_lines - 20)

    def lineHeight(self):
        metrics = self.fontMetrics()
        return metrics.lineSpacing()

    def adjustHeight(self):
        doc_height = int(self.document().size().height())
        line = self.lineHeight()
        line_count = max(1, int(doc_height / line))
        line_count = min(line_count, self.max_lines)
        new_height = line_count * line + 25
        self.setFixedHeight(new_height)


class ChatWindow(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.current_contact = None
        self.contacts = {}
        self.contact_avatars = {}
        self.prev_template = ''
        self.script_dir = Path(__file__).parent.parent
        self.init_ui()
        self.load_contacts()
        self.load_contact_settings()

    def init_ui(self):
        main_layout = QHBoxLayout(self)

        left_panel = QWidget()
        left_panel.setFixedWidth(220)
        left_layout = QVBoxLayout(left_panel)

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("🔍 Поиск в контактах")
        self.search_edit.setStyleSheet(style_input_field)
        self.search_edit.textChanged.connect(self.update_contacts_list)

        self.chats_list_widget = QListWidget()
        self.chats_list_widget.setStyleSheet(style_chat_list)

        add_chat_btn = QPushButton("⚙ Настройки")
        dobavit_contact = QPushButton("➕ Добавить контакт")
        dobavit_contact.setStyleSheet(style_round_btn)
        add_chat_btn.setStyleSheet(style_round_btn)

        left_layout.addWidget(self.search_edit)
        left_layout.addWidget(self.chats_list_widget)
        left_layout.addWidget(dobavit_contact)
        left_layout.addWidget(add_chat_btn)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)

        chat_header_layout = QHBoxLayout()

        self.chat_name_label = QLabel("Выберите чат для общения")
        self.chat_name_label.setStyleSheet("font-size: 16px; font-weight: bold; padding: 10px; ")
        self.chat_prefix_label = QLabel()
        self.chat_prefix_label.setFixedSize(60, 60)
        self.chat_prefix_label.setStyleSheet("""
            QLabel {
                border-radius: 30px;
                border: 2px solid #e0e0e0;
                background-color: transparent;
            }
        """)

        default_avatar_path = self.script_dir / "images" / "default_avatar.jpg"
        if os.path.exists(default_avatar_path):
            default_pixmap = QPixmap(str(default_avatar_path))
        else:
            default_pixmap = QPixmap(60, 60)
            default_pixmap.fill(QColor("#cccccc"))

        circular_pixmap = self.create_circular_pixmap(default_pixmap, 60)
        self.chat_prefix_label.setPixmap(circular_pixmap)
        self.chat_prefix_label.setScaledContents(True)

        settings_tool_btn = QToolButton()
        settings_tool_btn.setFixedSize(45, 45)
        settings_tool_btn.setStyleSheet(style_tool_button)
        image_path = self.script_dir / "images" / "3_points.png"
        if os.path.exists(image_path):
            settings_tool_btn.setIcon(QIcon(str(image_path)))
        settings_tool_btn.setIconSize(QSize(35, 35))

        settings_menu = QMenu(self)
        settings_menu.setStyleSheet(style_menu)

        del_chat = settings_menu.addAction("🗑️ Удалить из контактов")
        settings_menu.addSeparator()
        rename_chat = settings_menu.addAction("⚙ Изменить имя")

        settings_tool_btn.setMenu(settings_menu)
        settings_tool_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)

        chat_header_layout.addWidget(self.chat_prefix_label)
        chat_header_layout.addWidget(self.chat_name_label)
        chat_header_layout.addStretch()
        chat_header_layout.addWidget(settings_tool_btn)

        self.messages_text_browser = QWebEngineView()
        self.messages_text_browser.setStyleSheet(style_message_area1)

        input_panel_layout = QHBoxLayout()

        self.message_input_edit = AutoResizeTextEdit(max_lines=4)
        self.message_input_edit.setPlaceholderText("Введите сообщение...")
        self.message_input_edit.setStyleSheet(style_mesg)

        self.otpravka_btn = QPushButton()
        self.otpravka_btn.setFixedSize(40, 40)
        self.otpravka_btn.setStyleSheet(style_round_btn)
        image_path = self.script_dir / "images" / "otpravka.jpg"
        if os.path.exists(image_path):
            icon = QIcon(str(image_path))
            self.otpravka_btn.setIcon(icon)
            self.otpravka_btn.setIconSize(QSize(30, 30))

        input_panel_layout.addWidget(self.message_input_edit)
        input_panel_layout.addWidget(self.otpravka_btn)

        right_layout.addLayout(chat_header_layout)
        right_layout.addWidget(self.messages_text_browser)
        right_layout.addLayout(input_panel_layout)

        self.hi_label = QLabel("""Добро пожаловать в QuickTalk!

Прямое общение без лишнего шума.
Быстрый поиск по всем контактам,
удобное управление диалогами,
простота в использовании и
минималистичный дизайн.
Наслаждайтесь чистотой коммуникации!
        """)
        self.hi_label.setStyleSheet(style_hi_label)
        self.hi_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        main_layout.addWidget(left_panel)
        main_layout.addWidget(right_panel)
        main_layout.addWidget(self.hi_label)

        right_panel.hide()
        self.hi_label.show()

        self.current_right_widget = self.hi_label

        self.otpravka_btn.clicked.connect(self.send_message)
        add_chat_btn.clicked.connect(self.show_settings)

        self.chats_list_widget.itemClicked.connect(self.on_chat_selected)
        dobavit_contact.clicked.connect(self.add_contact_dialog)
        del_chat.triggered.connect(self.delete_chat)
        rename_chat.triggered.connect(self.rename_contact)

        self.message_input_edit.setFocus()

    def create_circular_pixmap(self, pixmap, size):
        circular_pixmap = QPixmap(size, size)
        circular_pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(circular_pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        path = QPainterPath()
        path.addEllipse(0, 0, size, size)
        painter.setClipPath(path)
        scaled_pixmap = pixmap.scaled(size, size,
                                      Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                                      Qt.TransformationMode.SmoothTransformation)

        x = 0
        y = 0
        if scaled_pixmap.width() > size:
            x = (scaled_pixmap.width() - size) // 2
        if scaled_pixmap.height() > size:
            y = (scaled_pixmap.height() - size) // 2

        painter.drawPixmap(0, 0, scaled_pixmap, x, y, size, size)
        painter.end()
        return circular_pixmap

    def load_contacts(self):
        response = make_server_request('get_contacts', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id
        })

        if response and response.get('success'):
            self.contacts = {}
            for contact_data in response['contacts']:
                contact = Contact(
                    login=contact_data['login'],
                    username=contact_data['username']
                )
                self.contacts[contact_data['login']] = contact
        self.update_contacts_list()

    def load_contact_settings(self):
        response = make_server_request('get_contact_settings', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id
        })
        if response and response.get('success'):
            settings = response.get('settings', {})
            for contact_login, setting in settings.items():
                if contact_login in self.contacts:
                    display_name = setting.get('display_name')
                    if display_name:
                        self.contacts[contact_login].display_name = display_name

            self.update_contacts_list()

    def load_contact_avatar(self, contact_login):
        if contact_login in self.contact_avatars:
            return self.contact_avatars[contact_login]

        response = make_server_request('get_avatar', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'contact_login': contact_login
        })

        if response and response.get('success'):
            avatar_data = response.get('avatar')
            if avatar_data:
                pixmap = QPixmap()
                pixmap.loadFromData(base64.b64decode(avatar_data))
                self.contact_avatars[contact_login] = pixmap
                return pixmap

    def search_users(self, search_query, dialog=None):
        response = make_server_request('search_users', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'search_query': search_query
        })

        if dialog and response and response.get('success'):
            dialog.results_list.clear()
            users = response.get('users', [])
            for user in users:
                item = QListWidgetItem(f"{user['username']} ({user['login']})")
                item.setData(Qt.ItemDataRole.UserRole, user)
                dialog.results_list.addItem(item)

            if not users:
                dialog.results_list.addItem("Пользователи не найдены")

    def get_user_info(self, login):
        response = make_server_request('get_user_info', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'target_login': login
        })

        if response and response.get('success'):
            return response.get('user')

    def search_contacts(self, search_text):
        search_text = search_text.strip().lower()
        result = []
        for contact in self.contacts.values():
            display_name = contact.get_display_name().lower()
            if not search_text or search_text in display_name:
                result.append(contact.get_display_name())
        return result

    def update_contacts_list(self):
        search_text = self.search_edit.text()
        filtered_contacts = self.search_contacts(search_text)
        self.chats_list_widget.clear()
        self.chats_list_widget.addItems(filtered_contacts)
        if search_text and not filtered_contacts:
            self.chats_list_widget.addItem("Контакты не найдены")

    def on_chat_selected(self, item):
        display_name = item.text()
        if display_name == "Контакты не найдены":
            return

        selected_contact = None
        for cont in self.contacts.values():
            if cont.get_display_name() == display_name:
                selected_contact = cont
                break

        if not selected_contact:
            return

        self.chat_name_label.setText(display_name)
        self.current_contact = selected_contact
        avatar_pixmap = self.load_contact_avatar(selected_contact.login)
        circular_icon = self.create_circular_pixmap(avatar_pixmap, 52)
        self.chat_prefix_label.setPixmap(circular_icon)

        if self.current_right_widget == self.hi_label:
            self.hi_label.hide()
            right_panel = self.layout().itemAt(1).widget()
            right_panel.show()
            self.current_right_widget = right_panel

        self.load_chat_history()
        self.message_input_edit.setFocus()

    def load_chat_history(self):
        if not self.current_contact:
            return
        response = make_server_request('get_messages', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'other_user_login': self.current_contact.login
        })

        if response and response.get('success'):
            messages = response.get('messages', [])
            template_path = self.script_dir / "chats" / "messages.html"
            if os.path.exists(template_path):
                with open(template_path, 'r', encoding='utf-8') as f:
                    template_content = f.read()
                    template = Template(template_content)
            else:
                template = Template("""
                <html>
                <body>
                {% for message in messages %}
                    <div style="margin: 10px; padding: 10px; background-color: {% if message.sender_login == current_user %}#e6f7ff{% else %}#f0f0f0{% endif %}; border-radius: 10px;">
                        <strong>{{ message.sender_login }}</strong>: {{ message.message_text|safe }}
                    </div>
                {% endfor %}
                </body>
                </html>
                """)

            for elem in messages:
                elem['message_text'] = markdown.markdown(html.escape(elem['message_text']),
                                                         extensions=['nl2br', 'tables'])

            rendered_template = template.render(messages=messages, current_user=self.main_window.current_user)

            if rendered_template != self.prev_template:
                self.messages_text_browser.setHtml(rendered_template, QUrl("file://"))
                self.messages_text_browser.show()

            self.prev_template = rendered_template

    def add_contact_dialog(self):
        dialog = SearchDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            user = dialog.get_selected_user()
            if user:
                self.add_contact_by_login(user['login'])

    def add_contact_by_login(self, contact_login):
        if not contact_login:
            QMessageBox.warning(self, "Ошибка", "Введите логин пользователя!")
            return

        if contact_login == self.main_window.current_user:
            QMessageBox.warning(self, "Ошибка", "Нельзя добавить самого себя!")
            return

        if contact_login in self.contacts:
            QMessageBox.information(self, "Информация", "Этот контакт уже добавлен!")
            return

        user_info = self.get_user_info(contact_login)
        if not user_info:
            QMessageBox.warning(self, "Ошибка", "Пользователь не найден!")
            return

        response = make_server_request('add_contact', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'contact_login': contact_login
        })

        if response:
            if response.get('success'):
                new_contact = Contact(
                    login=contact_login,
                    username=user_info['username'])
                self.contacts[contact_login] = new_contact
                self.update_contacts_list()
                QMessageBox.information(self, "Успех", f"Контакт '{user_info['username']}' добавлен!")
        else:
            QMessageBox.warning(self, "Ошибка", "Ошибка соединения с сервером!")

    def delete_chat(self):
        reply = QMessageBox.question(self, 'Удаление чатa',
                                     f'Вы уверены, что хотите удалить чат с {self.current_contact.get_display_name()}?')

        if reply == QMessageBox.StandardButton.Yes:
            response = make_server_request('remove_contact', {
                'user_token': self.main_window.user_token,
                'user_id': self.main_window.user_id,
                'contact_login': self.current_contact.login
            })

            if response and response.get('success'):
                if self.current_contact.login in self.contacts:
                    del self.contacts[self.current_contact.login]

                if self.current_contact.login in self.contact_avatars:
                    del self.contact_avatars[self.current_contact.login]

                self.update_contacts_list()
                self.current_contact = None
                self.chat_name_label.setText("Выберите чат для общения")
                self.messages_text_browser.close()
                self.show_welcome_screen()
                QMessageBox.information(self, "Успех", "Чат удален!")

    def rename_contact(self):
        new_name, ok = QInputDialog.getText(self, "Переименование",
                                            "Введите новое имя для контакта:",
                                            text=self.current_contact.get_display_name())

        if ok and new_name and new_name != self.current_contact.get_display_name():
            response = make_server_request('save_contact_settings', {
                'user_token': self.main_window.user_token,
                'user_id': self.main_window.user_id,
                'contact_login': self.current_contact.login,
                'display_name': new_name
            })

            if response and response.get('success'):
                self.current_contact.display_name = new_name
                self.chat_name_label.setText(new_name)
                self.update_contacts_list()
                QMessageBox.information(self, "Успех", "Контакт переименован!")

    def show_welcome_screen(self):
        if self.current_right_widget != self.hi_label:
            self.current_right_widget.hide()
            self.hi_label.show()
            self.current_right_widget = self.hi_label

    def send_message(self):
        message = self.message_input_edit.toPlainText().strip()
        if message == "":
            QMessageBox.warning(self, "Ошибка", "Сообщение не может быть пустым")
            return

        response = make_server_request('send_message', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'receiver_login': self.current_contact.login,
            'text': message
        })

        if response and response.get('success'):
            self.message_input_edit.clear()
            self.load_chat_history()

    def show_settings(self):
        self.main_window.show_settings_window()