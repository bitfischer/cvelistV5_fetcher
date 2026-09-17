FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml ./
COPY app ./app
COPY web ./web

RUN pip install --no-cache-dir .

RUN useradd --system --create-home --uid 1000 appuser
COPY docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh

ENV CVELISTV5_DB_PATH=/data/cves.db
VOLUME ["/data"]

EXPOSE 8420

ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8420"]
