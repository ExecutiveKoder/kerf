FROM python:3.12-slim-bookworm

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV DASTDAY_HOME=/data \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

VOLUME /data
EXPOSE 8000 8080

CMD ["python", "main.py", \
     "--proxy-host", "0.0.0.0", \
     "--ui-host", "0.0.0.0", \
     "--db", "/data/dastday.db"]
