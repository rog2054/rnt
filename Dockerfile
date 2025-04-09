# Use an official Python runtime as the base image
FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the root directory contents, plus templates/, and static/
COPY app.py forms.py models.py extensions.py requirements.txt version.txt /app/
COPY templates/ /app/templates/
COPY static/ /app/static/

# Accept ENCRYPTION_KEY as a build argument
ARG ENCRYPTION_KEY
# Set it as an environment variable in the image
ENV ENCRYPTION_KEY=$ENCRYPTION_KEY

# Install dependencies from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port your Flask app will run on (default is 5000, adjust if needed)
EXPOSE 5000

# Command to run the Flask app
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--worker-class", "eventlet", "app:app"]
