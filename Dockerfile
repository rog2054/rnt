# Use an official Python runtime as the base image
FROM python:3.13.3-slim-bullseye

# Set the working directory inside the container
WORKDIR /app

# Prepare entrypoint script
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

# Copy the root directory contents, plus templates/, and static/ and certs
COPY app.py forms.py models.py extensions.py utils.py requirements.txt version.txt /app/
COPY templates/ /app/templates/
COPY static/ /app/static/
COPY migrations/env.py migrations/script.py.mako migrations/alembic.ini /app/migrations/
COPY migrations/versions/ /app/migrations/versions/
COPY certs/cert.pem certs/key.pem /app/certs/

# Accept ENCRYPTION_KEY as a build argument
ARG ENCRYPTION_KEY
# Set it as an environment variable in the image
ENV ENCRYPTION_KEY=$ENCRYPTION_KEY
ENV USE_SSL=true

# Install dependencies from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port your Flask app will run on (default is 5000, adjust if needed)
EXPOSE 5000


# Run migrations and start Gunicorn
ENTRYPOINT ["/app/entrypoint.sh"]
