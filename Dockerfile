# Production Dockerfile for STEALTHWALL
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (iptables for live blocking)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl iptables nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt uvicorn websockets redis prometheus-client

# Copy application source
COPY . .

# Set container environment defaults
ENV STEALTHWALL_ALLOW_NO_IPTABLES=1
ENV PORT=9377

EXPOSE 9377 4488

# Default entrypoint starts dashboard operations control plane
CMD ["python3", "stealthwall_cli.py", "dashboard", "--port", "9377"]
