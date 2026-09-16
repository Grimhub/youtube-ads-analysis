FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8000
WORKDIR /app
COPY requirements-lock.txt ./
RUN pip install --no-cache-dir -r requirements-lock.txt
RUN groupadd --gid 10001 connector && useradd --uid 10001 --gid connector --no-create-home connector
COPY auth.py settings.py google_api.py server.py container_start.py ./
RUN mkdir -p /data/oauth && chown -R connector:connector /data
EXPOSE 8000
CMD ["python", "container_start.py"]
