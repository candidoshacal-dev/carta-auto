FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN groupadd --system app && useradd --system --gid app --home-dir /app app && mkdir -p /data && chown -R app:app /app /data
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN chmod 755 /app/entrypoint.sh && chown -R app:app /app /data
USER app
EXPOSE 8000
ENTRYPOINT ["/app/entrypoint.sh"]
