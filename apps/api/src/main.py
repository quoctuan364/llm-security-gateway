import hashlib
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select

from apps.api.src.core.config import settings
from apps.api.src.core.database import AsyncSessionLocal, init_db
from apps.api.src.core.models import ApiKeyRecord
from apps.api.src.routers.admin import router as admin_router
from apps.api.src.routers.completions import router as completions_router
from apps.api.src.routers.guard import router as guard_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Initialize DB tables
    await init_db()

    # 2. Seed default demo key if table is empty (for immediate plug & play)
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(ApiKeyRecord).limit(1))
        existing_key = result.scalars().first()
        if not existing_key:
            demo_raw_key = "aegis_demo_test_key_standard_client"
            demo_hash = hashlib.sha256(demo_raw_key.encode("utf-8")).hexdigest()
            demo_record = ApiKeyRecord(
                id="demo-client-key-id",
                name="Default Demo Key",
                key_hash=demo_hash,
                prefix="aegis_demo",
                project_id="demo-project",
                role="client",
                rate_limit_rpm=60,
                daily_token_budget=100_000,
                is_active=True,
            )
            session.add(demo_record)
            await session.commit()

    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Production-Grade LLM Security Gateway & Privacy Firewall",
    lifespan=lifespan,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=[
        "X-Aegis-Security-Action",
        "X-Aegis-Risk-Score",
        "X-Aegis-Redaction-Count",
        "X-Aegis-Correlation-ID",
    ],
)

# Register routers
app.include_router(completions_router)
app.include_router(guard_router)
app.include_router(admin_router)


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "provider_mode": settings.PROVIDER_MODE,
    }


@app.get("/")
async def root():
    return {
        "service": "Aegis LLM Security Gateway & Privacy Firewall",
        "docs_url": "/docs",
        "health_url": "/health",
        "gateway_endpoint": "/v1/chat/completions",
    }
