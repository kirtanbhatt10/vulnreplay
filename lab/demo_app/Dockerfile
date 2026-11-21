FROM python:3.12-slim
RUN useradd --create-home --uid 10001 lab
WORKDIR /app
RUN pip install --no-cache-dir "fastapi>=0.115" "uvicorn>=0.30"
COPY app.py .
USER lab
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=3s --retries=10 CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8000/health'); sys.exit(0)"
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
