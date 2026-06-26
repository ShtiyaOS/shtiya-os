# Dockerfile
# ==============================================================================
# SHTIYA OS: NODE 01 - ASSURED WORKLOADS RUNTIME ENVIRONMENT
# ==============================================================================

# 1. Base Image: Leverage slim Python for minimized attack surface
FROM python:3.11-slim as builder

# 2. Prevent Python from buffering standard output and writing bytecode
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# 3. System dependencies for pg8000 and cryptography compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 4. Dependency caching layer
COPY requirements.txt .
# Compile wheels locally to accelerate the final stage image creation
RUN pip install --no-cache-dir --upgrade pip && \
    pip wheel --no-cache-dir --no-deps --wheel-dir /app/wheels -r requirements.txt

# 5. Final Stage Execution
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Establish a non-root user to satisfy strict Assured Workloads security policies
RUN groupadd -r shtiya_group && useradd -r -g shtiya_group shtiya_user

WORKDIR /app

# Copy compiled wheels from builder and install them cleanly
COPY --from=builder /app/wheels /wheels
COPY --from=builder /app/requirements.txt .
RUN pip install --no-cache /wheels/*

# 6. Establish application payload
COPY . /app/

# Transfer ownership of the execution directory to the non-root user
RUN chown -R shtiya_user:shtiya_group /app

# Drop privileges
USER shtiya_user

# 7. Expose default Cloud Run port and launch via Uvicorn
EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "4", "--proxy-headers"]