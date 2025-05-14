#!/bin/sh
# entrypoint.sh

# Run database migrations
flask db upgrade

# Start Gunicorn with conditional SSL based on USE_SSL
if [ "$USE_SSL" = "true" ]; then
    exec gunicorn \
        --bind 0.0.0.0:5000 \
        --worker-class eventlet \
        --workers 1 \
        --certfile /app/certs/cert.pem \
        --keyfile /app/certs/key.pem \
        app:app
else
    exec gunicorn \
        --bind 0.0.0.0:5000 \
        --worker-class eventlet \
        --workers 1 \
        app:app
fi