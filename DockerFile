# Use an official Python runtime as the base image
FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the root directory contents, plus templates/, and static/
COPY app.py forms.py models.py requirements.txt /app/
COPY templates/ /app/templates/
COPY static/ /app/static/

# Install dependencies from requirements file
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port your Flask app will run on (default is 5000, adjust if needed)
EXPOSE 5000

# Command to run the Flask app
CMD ["python", "app.py"]