FROM python:3.11.9-slim
WORKDIR /app

# Install dependensi sistem untuk PostgreSQL
RUN apt-get update && apt-get install -y \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements dari root ke container
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy seluruh folder (termasuk src, model, dll) ke container
COPY . .
