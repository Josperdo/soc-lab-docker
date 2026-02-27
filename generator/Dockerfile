FROM python:3.11-slim

LABEL maintainer="SOC Lab Docker"
LABEL description="Synthetic security event log generator"

WORKDIR /app

# Install dependencies first (layer cache optimization)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy generator source and supporting files
COPY generator.py .
COPY config.yaml .
COPY templates/ ./templates/

# Create output directory (bind-mounted at runtime)
RUN mkdir -p /var/log/soc-lab

ENTRYPOINT ["python", "generator.py"]
