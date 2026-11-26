# ---- Build Stage ----
FROM python:3.12-slim AS builder

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir --prefix=/install .

# ---- Runtime Stage ----
FROM python:3.12-slim

LABEL maintainer="DeceptEnv Authors"
LABEL description="Zero-privilege active defense daemon"

# Non-root user for security
RUN groupadd -r deceptenv && useradd -r -g deceptenv -m deceptenv

WORKDIR /home/deceptenv

COPY --from=builder /install /usr/local
COPY --from=builder /app/src/ ./src/

# Create default canary directory
RUN mkdir -p /home/deceptenv/.deceptenv_canaries && \
    chown -R deceptenv:deceptenv /home/deceptenv

USER deceptenv

# Health check on the web dashboard
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/status')" || exit 1

EXPOSE 8080

ENTRYPOINT ["deceptenv"]
CMD ["dashboard"]
