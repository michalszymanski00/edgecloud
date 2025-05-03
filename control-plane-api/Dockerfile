# ---- base image ----
        FROM python:3.12-slim

        # ---- working dir & env ----
        WORKDIR /app
        ENV PYTHONUNBUFFERED=1
        
        # ---- install system packages ----
        RUN apt-get update \
         && apt-get install -y --no-install-recommends curl \
         && rm -rf /var/lib/apt/lists/*
        
        # ---- install Python deps ----
        RUN pip install --no-cache-dir \
                fastapi==0.110.1 \
                uvicorn[standard]==0.29.0 \
                SQLAlchemy[asyncio]==2.0.29 \
                asyncpg==0.29.0 \
                cryptography==42.0.5 \
                alembic \
                psycopg2-binary \
                prometheus_client \
                starlette_exporter \
                apscheduler
        
        # ---- copy application code ----
        COPY src/ /app/src/
        ENV PYTHONPATH=/app/src
        
        # ---- copy Alembic config & migrations ----
        COPY alembic.ini  /app/alembic.ini
        COPY alembic/     /app/alembic/
        
        # ---- default expose ----
        EXPOSE 8443 8444
        
        # ---- entrypoint: run migrations then start app ----
        CMD ["sh", "-c", "alembic upgrade head && uvicorn control_plane_api.main:app --host 0.0.0.0 --port 8443"]        