FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY schemas ./schemas
COPY start.sh ./start.sh
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["bash", "start.sh"]
