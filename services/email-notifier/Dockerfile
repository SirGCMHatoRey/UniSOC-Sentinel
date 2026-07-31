FROM python:3.12-slim-bookworm AS builder
RUN pip install --no-cache-dir --upgrade pip
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt --target /install

FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
RUN groupadd -r siem --gid=1000 && useradd -r -g siem --uid=1000 --home-dir=/app --shell=/sbin/nologin siem
WORKDIR /app
COPY --from=builder /install /usr/local/lib/python3.12/site-packages
COPY src/ ./src/
USER siem
EXPOSE 8084
HEALTHCHECK --interval=30s --timeout=10s --retries=3 CMD curl -sf http://localhost:8084/health || exit 1
CMD ["python", "-m", "src.main"]
