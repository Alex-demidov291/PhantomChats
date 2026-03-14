import sys
import os
from pathlib import Path


def get_base_path():
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))


def get_data_path():
    # - папка для хранения данных приложения
    if sys.platform == 'win32':
        base = os.environ.get('APPDATA', Path.home())
    elif sys.platform == 'darwin':
        base = Path.home() / 'Library' / 'Application Support'
    else:
        base = os.environ.get('XDG_DATA_HOME', Path.home() / '.local' / 'share')

    path = Path(base) / 'PhantomChats'
    path.mkdir(parents=True, exist_ok=True)
    return path


BASE_PATH = get_base_path()
DATA_PATH = get_data_path()


def find_file(relative_path):
    candidates = [
        os.path.join(BASE_PATH, relative_path),
        os.path.join(os.path.dirname(sys.executable), relative_path),
        os.path.join(os.path.dirname(sys.executable), '_internal', relative_path),
    ]

    for path in candidates:
        if os.path.exists(path):
            return path

    debug_path = os.path.join(os.path.dirname(sys.executable), 'path_debug.txt')
    with open(debug_path, 'w', encoding='utf-8') as f:
        f.write(f"Искали файл: {relative_path}\n")
        f.write(f"BASE_PATH: {BASE_PATH}\n")
        f.write(f"sys.executable: {sys.executable}\n\n")
        f.write("Проверяли пути:\n")
        for p in candidates:
            f.write(f"  {'OK' if os.path.exists(p) else 'НЕТ'}: {p}\n")
        f.write("\nСодержимое BASE_PATH:\n")
        try:
            for item in os.listdir(BASE_PATH):
                f.write(f"  {item}\n")
        except Exception as e:
            f.write(f"  Ошибка: {e}\n")

    return None