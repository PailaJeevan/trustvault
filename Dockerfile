# For Fly.io / Render / Railway / any container host. Mount a persistent
# volume at /data so the database survives restarts.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    TV_ENV=production TV_DATABASE_PATH=/data/trustvault.db \
    TV_SECURE_COOKIES=1 TV_TRUSTED_PROXIES=1 TV_SQLITE_JOURNAL=WAL

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY scripts ./scripts
COPY wsgi.py docker-entrypoint.sh ./

RUN useradd --create-home --uid 10001 tv && mkdir -p /data && chown tv /data
USER tv

EXPOSE 10000
# Seeds the demo if the database is empty, then runs gunicorn on $PORT.
# 2 workers: SQLite serialises writes; more workers only add lock contention.
CMD ["sh", "./docker-entrypoint.sh"]
