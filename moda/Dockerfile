FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install --no-install-recommends -y libmagic1 \
    && rm -rf /var/lib/apt/lists/*

COPY . /app
RUN python -m pip install ".[dev]"

RUN mkdir -p /quarantine && chown -R 10001:10001 /quarantine /app
USER 10001:10001

EXPOSE 2525 8080 8081

CMD ["moda-gateway"]
