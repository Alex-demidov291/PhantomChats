from PyQt6.QtWidgets import QApplication, QMainWindow
from PyQt6.QtCore import QTimer
from styles import style_input_dialog
from authorization.login_window import LoginWindow
from authorization.register_window import RegisterWindow
from chats.chat_window import ChatWindow
from chats.settings_window import SettingsWindow
from PyQt6.QtWidgets import QApplication, QMessageBox
import sys
import traceback
import os

def catch_all_exceptions():
    def excepthook(exc_type, exc_value, exc_traceback):
        print(f"Поймана ошибка:\n{''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))}")

    sys.excepthook = excepthook

catch_all_exceptions()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.current_widget = None
        self.setFixedSize(470, 570)

        self.current_user = None
        self.user_token = None
        self.user_id = None
        self.username = None

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_messages)

        self.show_login_window()

    def show_login_window(self):
        self.timer.stop()
        self._clear_current_widget()
        self.login_window = LoginWindow(self)
        self.setCentralWidget(self.login_window.get_widget())
        self.current_widget = self.login_window

    def show_register_window(self):
        self._clear_current_widget()
        self.register_window = RegisterWindow(self)
        self.setCentralWidget(self.register_window.get_widget())
        self.current_widget = self.register_window

    def show_chat_window(self):
        self.timer.stop()
        self._clear_current_widget()
        self.setFixedSize(700, 600)
        self.chat_window = ChatWindow(self)
        self.setCentralWidget(self.chat_window)
        self.current_widget = self.chat_window
        self.timer.start(5000)

    def show_settings_window(self):
        self.timer.stop()
        self._clear_current_widget()
        self.setFixedSize(530, 600)
        self.settings_window = SettingsWindow(self)
        self.setCentralWidget(self.settings_window)
        self.current_widget = self.settings_window

    def update_messages(self):
        if hasattr(self, 'chat_window') and self.chat_window:
            self.chat_window.load_chat_history()

    def logout(self):
        self.timer.stop()
        self.current_user = None
        self.user_token = None
        self.user_id = None
        self.username = None
        self.show_login_window()

    def _clear_current_widget(self):
        if self.current_widget:
            if hasattr(self.current_widget, 'get_widget'):
                self.current_widget.get_widget().deleteLater()
            else:
                self.current_widget.deleteLater()
            self.current_widget = None


if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyleSheet(style_input_dialog)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())