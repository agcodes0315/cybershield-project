FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
ENV PYTHONPATH=/app
ENV PORT=8000
ENV APP_ENV=production

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        g++ \
        libmagic1 \
        nmap \
        yara \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY detection-engine/requirements.txt ./requirements.txt

RUN python -m pip install --upgrade \
        "pip<26" \
        "setuptools==80.9.0" \
        wheel \
    && python -m pip install \
        --no-build-isolation \
        -r requirements.txt

COPY detection-engine/app ./app
COPY services ./services

RUN touch ./services/__init__.py \
    && touch ./services/email_analyzer/__init__.py \
    && touch ./services/email_analyzer/app/__init__.py

EXPOSE 8000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]