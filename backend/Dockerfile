FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN useradd --create-home --uid 10001 vulnreplay
WORKDIR /app
COPY pyproject.toml ./
COPY vulnreplay ./vulnreplay
RUN pip install --upgrade pip && pip install .
COPY alembic.ini ./
COPY migrations ./migrations
USER vulnreplay
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=12 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')"
CMD ["sh", "-c", "alembic upgrade head && uvicorn vulnreplay.main:app --host 0.0.0.0 --port 8000 --proxy-headers"]
