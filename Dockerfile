FROM python:3.12-bookworm

WORKDIR /app

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DASTDAY_HOME=/data \
    KERF_DOCKER=1 \
    DISPLAY=:99

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && playwright install --with-deps chromium \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        xvfb \
        x11vnc \
        novnc \
        websockify \
        fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN chmod +x /app/docker-entrypoint.sh

VOLUME /data
EXPOSE 8000 8080 6080

ENTRYPOINT ["/app/docker-entrypoint.sh"]
