# ── Stage 1: Doxygen doc builder ────────────────────────────────────────────
# Generates docs/html/ from source code and discards doxygen/graphviz from the
# final image, keeping the runtime image small.
FROM python:3.11-slim-bookworm AS doc-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    doxygen \
    graphviz \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only what Doxygen needs (source + config + README).
# .dockerignore already excludes docs/, __pycache__, venv, etc.
COPY . .

RUN doxygen Doxyfile

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Runtime system dependencies only — no doxygen / graphviz here
RUN apt-get update && apt-get install -y --no-install-recommends \
    bluez \
    iw \
    libpcap-dev \
    procps \
    iproute2 \
    net-tools \
    ieee-data \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies before copying source so this layer is cached
# as long as requirements.txt does not change.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Inject the pre-built documentation from the builder stage
COPY --from=doc-builder /app/docs/html /app/docs/html

# DeviceWatcher HTTP API + docs
EXPOSE 5000

# Default command — override via docker-compose `command:` as needed
ENTRYPOINT ["python", "DeviceWatcher.py", "--host", "0.0.0.0", "--wifi", "wlan0mon", "--ble", "1"]
