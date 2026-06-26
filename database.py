# database.py
# ==============================================================================
# SHTIYA OS: NODE 01 - IAM AUTHENTICATED & RLS SECURED DATABASE CONNECTIONS
# ==============================================================================

import os
import logging
import pg8000
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy import text
from google.cloud.sql.connector import Connector, IPTypes

logger = logging.getLogger("ShtiyaOS_DB")

# Environment configurations mapped to Assured Workloads variables
INSTANCE_CONNECTION_NAME = os.environ.get("INSTANCE_CONNECTION_NAME")
DB_IAM_USER = os.environ.get("DB_IAM_USER")
DB_NAME = os.environ.get("DB_NAME", "shtiya_os_core")

# Initialize the GCP Connector.
connector = Connector(refresh_strategy="LAZY")

def getconn() -> pg8000.dbapi.Connection:
    """
    Initializes a connection pool for Cloud SQL Postgres using Automatic IAM Authentication.
    Utilizes Private IP (IPTypes.PRIVATE) ensuring no public internet exposure.
    """
    pg8000.dbapi.paramstyle = "pyformat"
    try:
        conn = connector.connect(
            INSTANCE_CONNECTION_NAME,
            "pg8000",
            user=DB_IAM_USER,
            db=DB_NAME,
            enable_iam_auth=True,
            ip_type=IPTypes.PRIVATE
        )
        return conn
    except Exception as e:
        logger.error(f"Failed to establish secure IAM database connection: {str(e)}")
        raise

# Initialize SQLAlchemy async engine
engine = create_async_engine(
    "postgresql+pg8000://",
    creator=getconn,
    pool_size=20,
    max_overflow=10,
    pool_timeout=30,
    pool_recycle=1800, # Recycle connections every 30 minutes to mitigate stale IAM tokens
    echo=False
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)

async def get_secure_db_session(tenant_id: str, matter_id: str = None) -> AsyncSession:
    """
    Dependency injection generator providing an AsyncSession strictly bound
    to the authenticated user's RLS constraints.
    """
    async with AsyncSessionLocal() as session:
        # Atomic transaction enforcement guarantees session variables do not bleed.
        async with session.begin():
            # Apply the restricted backend role
            await session.execute(text("SET LOCAL ROLE shtiya_backend_role"))

            # Inject cryptographic RLS context
            await session.execute(text(f"SET LOCAL app.current_tenant = '{tenant_id}'"))
            if matter_id:
                await session.execute(text(f"SET LOCAL app.current_matter = '{matter_id}'"))

            try:
                yield session
            finally:
                # Context is inherently discarded when the transaction block exits.
                pass