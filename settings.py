import os
import secrets
# Client settings
SERVER_URL = 'https://hell-0.ru:6666'

# Server settings
RUNNING_PORT = 5000
SERVER_HOST = '0.0.0.0'

# Common settings
DEBUG = False

SESSION_HASH_SALT = os.environ.get("SESSION_HASH_SALT")
if not SESSION_HASH_SALT:
    SESSION_HASH_SALT = secrets.token_hex(32)