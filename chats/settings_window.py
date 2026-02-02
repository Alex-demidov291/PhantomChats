from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
                             QLineEdit, QFileDialog, QMessageBox)
from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.QtCore import QSize, Qt
import sys
import os
import tempfile
import base64
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from styles import (style_round_btn, style_reg_button, style_login_button, style_red_button,
                    style_input_field, defult_ava, angle_alf, numbers)
from network import make_server_request


class SettingsWindow(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.current_avatar_path = defult_ava
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)

        title_label = QLabel("Настройки профиля")
        title_label.setStyleSheet("font-size: 20px; font-weight: bold; padding: 10px; text-align: center;")
        main_layout.addWidget(title_label)

        avatar_layout = QHBoxLayout()
        avatar_label = QLabel("Аватар:")
        avatar_label.setStyleSheet("font-size: 16px; padding: 10px;")

        self.avatarka = QPushButton()
        self.avatarka.setFixedSize(150, 150)
        self.avatarka.setStyleSheet(style_round_btn)

        response = make_server_request('info', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id
        })
        if response and response.get('success'):
            avatar_data = response.get('avatar')
            if avatar_data and avatar_data != 'default_avatar.jpg':
                self.current_avatar_path = self.save_temp_avatar(avatar_data)

        icon = QIcon(self.current_avatar_path)
        self.avatarka.setIcon(icon)
        self.avatarka.setIconSize(QSize(140, 140))

        change_avatar_btn = QPushButton("Изменить аватар")
        change_avatar_btn.setStyleSheet(style_reg_button)

        avatar_layout.addWidget(avatar_label)
        avatar_layout.addWidget(self.avatarka)
        avatar_layout.addWidget(change_avatar_btn)
        main_layout.addLayout(avatar_layout)

        name_title = QLabel("Смена имени:")
        name_title.setStyleSheet("font-size: 16px; padding: 10px; font-weight: bold;")

        name_input_layout = QHBoxLayout()
        self.name_edit = QLineEdit()
        self.name_edit.setStyleSheet(style_input_field)
        self.name_edit.setPlaceholderText("Введите новое имя")
        self.name_edit.setText(self.main_window.username)

        change_name_btn = QPushButton("Изменить имя")
        change_name_btn.setStyleSheet(style_reg_button)

        name_input_layout.addWidget(self.name_edit)
        name_input_layout.addWidget(change_name_btn)

        name_layout = QVBoxLayout()
        name_layout.addWidget(name_title)
        name_layout.addLayout(name_input_layout)
        main_layout.addLayout(name_layout)

        password_title = QLabel("Смена пароля:")
        password_title.setStyleSheet("font-size: 16px; padding: 10px; font-weight: bold;")

        password_input_layout = QHBoxLayout()
        self.password_edit = QLineEdit()
        self.password_edit.setStyleSheet(style_input_field)
        self.password_edit.setPlaceholderText("Введите новый пароль")
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)

        change_password_btn = QPushButton("Изменить пароль")
        change_password_btn.setStyleSheet(style_reg_button)

        password_input_layout.addWidget(self.password_edit)
        password_input_layout.addWidget(change_password_btn)

        password_layout = QVBoxLayout()
        password_layout.addWidget(password_title)
        password_layout.addLayout(password_input_layout)
        main_layout.addLayout(password_layout)

        back_chat_btn = QPushButton("Вернуться в чат")
        back_chat_btn.setStyleSheet(style_login_button)
        main_layout.addWidget(back_chat_btn)

        back_log_btn = QPushButton("Выйти")
        back_log_btn.setStyleSheet(style_red_button)
        main_layout.addWidget(back_log_btn)

        change_name_btn.clicked.connect(self.change_name)
        change_password_btn.clicked.connect(self.change_password)
        back_chat_btn.clicked.connect(self.show_chat_window)
        back_log_btn.clicked.connect(self.logout)
        change_avatar_btn.clicked.connect(self.change_avatar)

    def save_temp_avatar(self, avatar_data):
        try:
            avatar_bytes = base64.b64decode(avatar_data)
            temp_path = os.path.join(tempfile.gettempdir(), 'temp_avatar.png')
            with open(temp_path, 'wb') as f:
                f.write(avatar_bytes)
            return temp_path
        except Exception as e:
            print(f"Error saving temp avatar: {e}")
            return defult_ava

    def change_name(self):
        new_name = self.name_edit.text().strip()

        if len(new_name) < 4 or len(new_name) > 16:
            QMessageBox.warning(self, "Ошибка", "Имя должно содержать минимум 4, максимум 16 символов!")
            return

        correct_name = False

        for el in new_name:
            if el in angle_alf or el in angle_alf.upper() or el in numbers or el == "_":
                correct_name = True
            else:
                correct_name = False

        if not correct_name:
            QMessageBox.warning(self, "Ошибка",
                                "Имя должно содержать маленькие и заглавные англ. буквы или цифры или же _ !")
            return

        response = make_server_request('update_profile', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'username': new_name
        })

        if response:
            if response.get('success'):
                self.main_window.username = new_name
                QMessageBox.information(self, "Успех", "Имя успешно изменено!")
            else:
                error_msg = response.get('error', 'Неизвестная ошибка')
                QMessageBox.warning(self, "Ошибка", f"Ошибка при смене имени: {error_msg}")
        else:
            QMessageBox.warning(self, "Ошибка", "Ошибка соединения с сервером!")

    def change_avatar(self):
        fname = QFileDialog.getOpenFileName(
            self, 'Выбрать аватар', '',
            'Изображения (*.jpg *.jpeg *.png *.gif *.bmp *.webp)')[0]

        if fname:
            try:
                pixmap = QPixmap(fname)
                max_size = 200
                if pixmap.width() > max_size or pixmap.height() > max_size:
                    pixmap = pixmap.scaled(max_size, max_size,
                                           Qt.AspectRatioMode.KeepAspectRatio,
                                           Qt.TransformationMode.SmoothTransformation)

                import tempfile
                temp_dir = tempfile.gettempdir()
                temp_path = os.path.join(temp_dir, 'temp_avatar_compressed.jpg')
                pixmap.save(temp_path, "JPEG", quality=80)

                with open(temp_path, 'rb') as f:
                    image_data = f.read()

                os.remove(temp_path)

                if len(image_data) > 1000000:  # 1MB
                    QMessageBox.warning(self, "Ошибка",
                                        "Изображение слишком большое. Выберите файл поменьше.")
                    return

                avatar_base64 = base64.b64encode(image_data).decode('utf-8')

                response = make_server_request('update_profile', {
                    'user_token': self.main_window.user_token,
                    'user_id': self.main_window.user_id,
                    'avatar': avatar_base64
                })

                if response:
                    if response.get('success'):
                        icon = QIcon(fname)
                        self.avatarka.setIcon(icon)
                        self.avatarka.setIconSize(QSize(140, 140))
                        self.current_avatar_path = fname
                        QMessageBox.information(self, "Успех", "Аватарка успешно изменена!")
                    else:
                        error_msg = response.get('error', 'Неизвестная ошибка')
                        QMessageBox.warning(self, "Ошибка", f"Ошибка при сохранении аватарки: {error_msg}")
                else:
                    QMessageBox.warning(self, "Ошибка", "Ошибка соединения с сервером!")

            except Exception as e:
                QMessageBox.warning(self, "Ошибка", f"Ошибка при загрузке аватарки: {str(e)}")

    def change_password(self):
        new_password = self.password_edit.text()

        if len(new_password) < 6 or len(new_password) > 16:
            QMessageBox.warning(self, "Ошибка", "Пароль должен содержать минимум 6, максимум 16 символов!")
            return

        number_for_pass = False
        zagl_for_pass = False
        low_for_pass = False

        for el in new_password:
            if el in numbers or el == "_":
                number_for_pass = True
            elif el in angle_alf:
                low_for_pass = True
            elif el in angle_alf.upper():
                zagl_for_pass = True
            else:
                number_for_pass = False
                zagl_for_pass = False
                low_for_pass = False

        if not number_for_pass or not zagl_for_pass or not low_for_pass:
            QMessageBox.warning(self, "Ошибка",
                                "Пароль должен содержать маленькие и заглавные англ. буквы, а так же цифры или _ !")
            return

        response = make_server_request('update_profile', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'password': new_password
        })

        if response and response.get('success'):
            self.password_edit.clear()
            QMessageBox.information(self, "Успех", "Пароль успешно изменен!")

    def show_chat_window(self):
        self.main_window.show_chat_window()

    def logout(self):
        self.main_window.logout()