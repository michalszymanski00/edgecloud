# ---- base image ----
    FROM python:3.12-slim

    # ---- working dir & env ----
    WORKDIR /app
    ENV PYTHONUNBUFFERED=1
    
    # ---- install system packages needed by our health-check ----
    RUN apt-get update \
     && apt-get install -y --no-install-recommends curl \
     && rm -rf /var/lib/apt/lists/*
    
    # ---- install Python deps (pin versions) ----
    RUN pip install --no-cache-dir \
            fastapi==0.110.1 \
            uvicorn[standard]==0.29.0 \
            SQLAlchemy[asyncio]==2.0.29 \
            asyncpg==0.29.0 \
            cryptography==42.0.5
    
    # ---- copy application code ----
    COPY src/ /app/src/
    ENV PYTHONPATH=/app/src
    
    # ---- default expose (not used in compose) ----
    EXPOSE 8443 8444
    CMD ["uvicorn", "control_plane_api.main:app", "--host", "0.0.0.0", "--port", "8443"]    