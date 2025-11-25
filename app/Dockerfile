FROM python:3.9-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Copy requirements first for better caching (if present)
COPY requirements.txt /app/requirements.txt

# Install runtime dependencies: ensure flask and json-logging are present
RUN pip install --no-cache-dir --upgrade pip \
	&& pip install --no-cache-dir flask json-logging -r /app/requirements.txt

# Copy application code
COPY . /app

EXPOSE 5000

CMD ["python", "app.py"]
