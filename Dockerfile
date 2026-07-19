FROM python:3.12-slim AS application

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV ONE_MIND_DATA_DIR=/app/data

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        sqlite3 \
        curl \
        procps && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY static ./static
COPY scripts ./scripts

RUN chmod +x /app/scripts/entrypoint.sh

EXPOSE 8443

FROM application AS test

COPY tests ./tests

CMD ["python", "-m", "unittest", "discover", "-s", "tests", "-v"]

FROM application AS production

CMD ["/app/scripts/entrypoint.sh"]
