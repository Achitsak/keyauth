FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DB_PATH=/data/keyauth.db

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app

# SQLite lives on a mounted volume so it survives container restarts.
VOLUME ["/data"]

EXPOSE 8000

# Single robust worker; the orchestrator restarts on crash.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
