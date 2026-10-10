# Stage 1: build the React dashboard.
FROM node:22-slim AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend ./
RUN npm run build

# Stage 2: Python app with tshark and openssl, serving the dashboard and API on one port.
FROM python:3.12-slim-trixie
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    QTRACE_SCAN_ROOTS=/data:/app/sample-repos:/app/cloud-posture:/app/network-capture
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends tshark openssl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Editable install: the knowledge base ships .csv and .json files that pyproject package-data does not list.
COPY pyproject.toml ./
COPY src ./src
RUN pip install -e .
COPY api ./api
COPY tests/fixtures/scan_result_sample.json ./tests/fixtures/scan_result_sample.json
COPY sample-repos ./sample-repos
COPY cloud-posture ./cloud-posture
COPY network-capture ./network-capture
COPY --from=ui /ui/dist ./frontend/dist
EXPOSE 8000
# Default: dashboard and API. Override with `qtrace scan ...`.
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
