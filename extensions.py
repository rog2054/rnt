from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
from flask_babel import Babel
from flask_babel import lazy_gettext as _l
import os

# Define db
db = SQLAlchemy()
babel = Babel()

# Setup encryption
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY must be set in environment")
ENCRYPTION_KEY = ENCRYPTION_KEY.encode()  # Convert to bytes if needed
cipher = Fernet(ENCRYPTION_KEY)
  