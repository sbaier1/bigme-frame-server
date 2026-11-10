FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt pillow-heif

COPY server.py .
RUN mkdir -p /app/photos

EXPOSE 8086

CMD ["python", "server.py"]
