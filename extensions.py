from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
import os

# Define db
db = SQLAlchemy()

# Setup encryption
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY') or Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)