from PyQt6.QtWidgets import QWidget, QMessageBox
from PyQt6 import uic
import sys
import os
from pathlib import Path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from styles import style_input_field, style_login_button, style_reg_button
from network import make_server_request


class LoginWindow(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.init_ui()

    def init_ui(self):
        current_dir = Path(__file__).parent
        ui_path = str(current_dir / 'log_wind.ui')
        self.widget = uic.loadUi(ui_path)

        self.widget.Log_Input1.setStyleSheet(style_input_field)
        self.widget.Password_Input1.setStyleSheet(style_input_field)
        self.widget.Login_Button.setStyleSheet(style_login_button)
        self.widget.Reg_Button1.setStyleSheet(style_reg_button)

        self.widget.Login_Button.clicked.connect(self.check_log)
        self.widget.Log_Input1.setPlaceholderText("Введите ваш логин")

        self.widget.Password_Input1.setPlaceholderText("Введите ваш пароль")
        self.widget.Reg_Button1.clicked.connect(self.show_register_window)

    def check_log(self):
        login = self.widget.Log_Input1.text()
        password = self.widget.Password_Input1.text()

        if not login or not password:
            QMessageBox.warning(self, "Ошибка", "Заполните все поля!")
            return

        response = make_server_request('login', {
            'login': login,
            'password': password
        })

        if response:
            if response.get('success'):
                required_fields = ['user_token', 'user_id', 'username']
                missing_fields = [field for field in required_fields if field not in response]

                if missing_fields:
                    print(f"ERROR: {missing_fields}")
                    QMessageBox.warning(self, "Ошибка",
                                        f"Сервер вернул неполный ответ. Отсутствуют: {', '.join(missing_fields)}")
                    return

                self.main_window.user_token = response['user_token']
                self.main_window.user_id = response['user_id']
                self.main_window.username = response['username']
                self.main_window.current_user = login
                self.main_window.show_chat_window()
                self.close()
            else:
                error_msg = response.get('error', 'Неизвестная ошибка')
                QMessageBox.warning(self, "Ошибка", error_msg)
        else:
            QMessageBox.warning(self, "Ошибка", "Ошибка соединения с сервером!")

    def show_register_window(self):
        self.main_window.show_register_window()

    def get_widget(self):
        return self.widget