# main.py
# ==============================================================================
# SHTIYA OS: NODE 01 - FASTAPI ENTRYPOINT
# ==============================================================================

from fastapi import FastAPI, Depends, APIRouter, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import logging

from database import get_secure_db_session, engine
from dependencies import verify_external_api_throughput
from cache import redis_client

logger = logging.getLogger("ShtiyaOS_Main")

app = FastAPI(
    title="Shtiya OS Legal & Medical Core",
    version="1.8.4",
    description="HIPAA-compliant Core API for Node 01 Processing"
)

# Strict CORS for Node 04 IDE
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://ide.shtiya.internal"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

router = APIRouter(prefix="/api/v1")

@router.get("/health", summary="Infrastructure Boundary Health Check")
async def health_check():
    """Validates connectivity across the Zero-Trust network."""
    db_status = "unavailable"
    cache_status = "unavailable"
    
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception as e:
        logger.error(f"DB Healthcheck failed: {str(e)}")
        
    try:
        await redis_client.ping()
        cache_status = "ok"
    except Exception as e:
        logger.error(f"Cache Healthcheck failed: {str(e)}")

    return {
        "boundary_status": "SECURE",
        "cloud_sql": db_status,
        "memorystore": cache_status
    }

@router.post("/clio/sync", dependencies=[Depends(verify_external_api_throughput)])
async def trigger_clio_synchronization(request: Request):
    """
    Triggers outbound synchronization, protected by sliding-window throttling.
    """
    user_id = request.headers.get("X-Clio-User-ID")
    logger.info(f"Initiating synchronization pipeline for user {user_id}")
    # Dispatch to Celery worker...
    return {"status": "Synchronization enqueued safely"}

app.include_router(router)