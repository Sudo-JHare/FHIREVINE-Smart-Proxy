# Dockerfile for FHIRVINE (Single Stage - Log pip install)

# Use Python 3.11 Bullseye base image
FROM python:3.11-bullseye

# Set environment variables using recommended key=value format
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /app

# Install system dependencies (needed if any Python package requires compilation)
# Keep build-essential just in case
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for caching layer optimization
COPY requirements.txt .

# Ensure pip is up-to-date
RUN pip install --no-cache-dir --upgrade pip

# Install dependencies directly from requirements.txt
# Redirect stdout and stderr to a log file
# Use --force-reinstall for Authlib as an extra measure
# Using Authlib 1.5.2 as 1.2.0 had Werkzeug incompatibility
RUN pip install --no-cache-dir -r requirements.txt --force-reinstall Authlib==1.5.2 > /pip_install.log 2>&1 || (cat /pip_install.log && exit 1)

# Copy the rest of the application code
COPY . .

# Create a non-root user and group
RUN groupadd -r appuser && useradd --no-log-init -r -g appuser appuser

# Create the instance directory
RUN mkdir -p instance

# Change ownership AFTER creating instance dir and copying code
RUN chown -R appuser:appuser /app

# Switch to the non-root user
USER appuser

# Expose the port
EXPOSE 5001

# Define the command to run the application
CMD exec /usr/local/bin/waitress-serve --host=0.0.0.0 --port=5001 --call 'app:create_app'
