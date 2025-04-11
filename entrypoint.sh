#!/bin/sh
# entrypoint.sh

# Run database migrations
flask db upgrade

# Start Gunicorn using exec to replace the shell with the Gunicorn process
exec gunicorn --bind 0.0.0.0:5000 --worker-class eventlet app:app
