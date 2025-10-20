# Liffy Enhanced Dockerfile
FROM python:3.9-slim

# Set metadata
LABEL maintainer="Liffy Enhanced Team"
LABEL version="2.0.0"
LABEL description="Ultimate Local File Inclusion Exploitation Tool"

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    netcat-openbsd \
    net-tools \
    iputils-ping \
    telnet \
    dnsutils \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Note: Metasploit Framework needs to be installed separately
# For payload generation features, install metasploit-framework on the host system

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --timeout=300 -r requirements.txt

# Install additional dependencies for API mode
RUN pip install --no-cache-dir --timeout=300 flask flask-cors aiohttp

# Copy application files
COPY . .

# Create necessary directories
RUN mkdir -p /app/data /app/logs /app/config

# Make scripts executable
RUN chmod +x *.py *.sh

# Create non-root user
RUN useradd -m -u 1000 liffy && \
    chown -R liffy:liffy /app

# Switch to non-root user
USER liffy

# Expose ports
EXPOSE 8000 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 liffy_enhanced.py --help || exit 1

# Default command
CMD ["python3", "liffy_enhanced.py", "--help"]
