FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Render fournit $PORT. Fallback à 8000 en local.
CMD ["sh", "-c", "uvicorn app.worker:app --host 0.0.0.0 --port ${PORT:-8000}"]
