from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
import os

# Define db
db = SQLAlchemy()

# Setup encryption
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY must be set in environment")
ENCRYPTION_KEY = ENCRYPTION_KEY.encode()  # Convert to bytes if needed
cipher = Fernet(ENCRYPTION_KEY)
