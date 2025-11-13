# Lightweight production image for the Flask web UI
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# System deps (if needed later). Keep minimal for security.
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first for better caching
COPY vuln_scanner/requirements.txt /app/requirements.txt
RUN python -m pip install --upgrade pip \
    && pip install -r /app/requirements.txt

# Copy project
COPY vuln_scanner /app/vuln_scanner
WORKDIR /app/vuln_scanner

# Default port for containerized app; platforms usually set $PORT
ENV PORT=8000
EXPOSE 8000

# Start via Gunicorn, importing the Flask app object.
# Use shell form so $PORT (injected by platforms like Render) expands; default to 8000.
CMD gunicorn --bind 0.0.0.0:${PORT:-8000} webapp.app:app
