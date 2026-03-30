# Byte-Shield — imagen ligera (API por defecto; sobrescribir comando para CLI)
FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY pyproject.toml README.md ./
COPY src ./src
COPY compliance ./compliance

RUN pip install --no-cache-dir -e ".[api]"

EXPOSE 8000

# API: byteshield-api | CLI: byteshield --target HOST --ports 443
CMD ["byteshield-api"]
