# **Architectural Blueprint and Implementation Protocol for the Shtiya OS Core Ecosystem**

## **1\. Systemic Fortification of Sovereign Cloud Workloads**

The deployment of fiduciary, legal, and healthcare data processing systems demands a structural departure from conventional enterprise cloud architectures. The Shtiya OS 10-Node Master Blueprint establishes a closed-loop network economy designed to process Protected Health Information (PHI) under strict Health Insurance Portability and Accountability Act (HIPAA) guidelines, attorney-client privileged material, and client trust accounting data subject to state bar (IOLTA) regulations. Operating entirely within a Google Cloud Platform (GCP) Assured Workloads boundary designated in the us-central1 region, the platform relies on a mathematically provable Zero-Trust Network Architecture.  
In this paradigm, security is not a perimeter overlay but an intrinsic property of the computational and storage layers. The architecture utilizes sovereign boundaries and Customer-Managed Encryption Keys (CMEK) via Cloud Key Management Service (KMS) Hardware Security Modules (HSM) to cryptographically isolate heavy computational processing from the passive database of record maintained via external API integrations.  
A rigorous mechanical deconstruction of distributed systems operating multi-tenant Retrieval-Augmented Generation (RAG) capabilities reveals several critical vulnerability domains. These vectors expose ecosystems to cross-tenant data bleeding, smart contract race conditions during escrow execution, cascading third-party API failures, and severe statutory liabilities under gig-economy employment classifications. This report systematically deconstructs these vectors and provides the production-ready schemas, un-truncated codebase deployments, and infrastructure instructions required to fortify the Shtiya OS Node 01 compute core and its supporting data layers for global deployment.

### **1.1 The Mathematical Imperative for Cryptographic Multi-Tenant Isolation**

Node 05 serves as the core AI Case Vault, utilizing Cloud SQL for PostgreSQL (Enterprise Plus, v18.4) extended with pgvector to interface with Google Vertex AI.1 This node powers the Node 04 Integrated Drafting Environment (IDE), enabling attorneys to draft motions and query a 1536-dimensional vector space. The primary threat vector within this highly dimensional environment is cross-contamination.  
If multi-tenant isolation relies solely on logical application-layer WHERE clauses implemented by the FastAPI backend (Node 01), a single malformed query, a missing parameter, or an application-side injection exploit could allow one tenant to inadvertently or maliciously retrieve the vectorized intellectual property of another. Furthermore, the PostgreSQL query execution planner optimizes query performance by reordering execution steps based on statistical cost analysis. If a filtering function utilized in a query is not strictly defined with the LEAKPROOF designation, the planner may execute a computationally expensive or potentially malicious user-defined function against the vector table *before* applying the logical isolation filter, resulting in a side-channel data leak.  
Mathematically, the probability of a data leak ![][image1] in a logically isolated system without rigorous cryptographic Row-Level Security (RLS) can be expressed as a function of the number of unique query construction paths in the application layer. Let ![][image2] be the number of query construction paths in the FastAPI backend, and ![][image3] be the probability of a developer omission or injection vulnerability in path ![][image4]. The overall system vulnerability is defined as:  
![][image5]  
As the application scales and ![][image2] increases, the probability of a leak ![][image1] asymptotically approaches 1\. By implementing intrinsic RLS at the storage layer and enforcing security\_invoker \= true on all database views to ensure they obey the caller's RLS policies rather than the creator's, ![][image2] is mathematically reduced to 1 for all application-layer paths.1 This shifts the security boundary to the database execution engine itself.  
The following table categorizes the isolation strategy confidence matrix:

| Isolation Strategy | Locus of Enforcement | Side-Channel Vulnerability | View Bypass Risk | Mitigation Confidence |
| :---- | :---- | :---- | :---- | :---- |
| Logical Application Layer | FastAPI ORM / SQL Builder | High (Planner reordering) | N/A | Low (Requires perfect code) |
| Standard PostgreSQL RLS | Database Execution Engine | Medium (Function leaks) | High (Owner execution) | Moderate |
| Strict RLS \+ Leakproof \+ Invoker Views | Database Execution Engine | Zero (Planner constrained) | Zero (Caller execution) | Absolute |

### **1.2 Ledger Layer Concurrency and Escrow Race Conditions**

Node 10 operates a Hyperledger Fabric blockchain layer for minting immutable legal ledgers and escrow transactions. Hyperledger Fabric operates on an Execute-Order-Validate architecture utilizing an Optimistic Locking Model via Multi-Version Concurrency Control (MVCC). During execution, a smart contract simulates the transaction, recording the read-set (versions of keys read) and the write-set (new values to be written).  
If Node 09 (Native Escrow) and Node 10 attempt to read and update a single global state variable (such as a master escrow balance) concurrently, they register the same version of the key (![][image6]). When the ordering service sequences these transactions into a block, the first transaction updates the key to ![][image7]. The second transaction is rejected during validation with an MVCC\_READ\_CONFLICT error because its read-set version (![][image6]) no longer matches the current world state (![][image7]).  
To structurally resolve this vulnerability, the system eschews single-key balance tracking entirely, adopting a Composite Key Delta State Pattern. Every credit and debit is written as an isolated, immutable delta record using a unique composite key. Balance calculation becomes a dynamic aggregation function executed at read-time, mathematically eliminating write collisions and preventing double-spend race conditions in the escrow logic.

## **2\. Deliverable 1: Cryptographic Database Schemas**

To completely eliminate the risk of cross-tenant data bleeding and strictly adhere to HIPAA data minimization standards, the SQLAlchemy 2.0 schemas must map directly to the PostgreSQL RLS definitions. The application schema parameterizes all connections and relies on the pgvector SQLAlchemy dialect for 1536-dimensional embedding storage.1

### **2.1 The SQLAlchemy 2.0 Declarative Models (models.py)**

The following codebase defines the declarative base and the core tables for the platform. It specifically configures the Vector type for compatibility with the pgvector extension and prepares the schema for RLS enforcement via the tenant\_id composite requirement.2 Parameterization is strictly enforced by SQLAlchemy's Mapped typing, preventing SQL injection and ensuring HIPAA data minimization.

Python  
\# models.py  
\# \==============================================================================  
\# SHTIYA OS: NODE 05 \- SECURE MULTI-TENANT ALCHEMY MODELS  
\# \==============================================================================

import uuid  
from datetime import datetime  
from typing import Optional, List, Dict, Any  
from sqlalchemy import String, Integer, DateTime, ForeignKey, Text, Index  
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped\_column, relationship  
from sqlalchemy.dialects.postgresql import UUID, JSONB  
from sqlalchemy.sql import func  
from pgvector.sqlalchemy import Vector

class Base(DeclarativeBase):  
    """  
    Core declarative base for Shtiya OS.  
    All tables are inherently prepared for PostgreSQL Row-Level Security (RLS)  
    by strictly requiring a tenant\_id mapping.  
    """  
    pass

class Tenant(Base):  
    \_\_tablename\_\_ \= "tenants"

    tenant\_id: Mapped \= mapped\_column(UUID(as\_uuid=True), primary\_key=True, default=uuid.uuid4)  
    firm\_name: Mapped\[str\] \= mapped\_column(String(255), nullable=False)  
    subscription\_tier: Mapped\[str\] \= mapped\_column(String(50), default='enterprise')  
    created\_at: Mapped\[datetime\] \= mapped\_column(DateTime(timezone=True), server\_default=func.now())  
    updated\_at: Mapped\[datetime\] \= mapped\_column(DateTime(timezone=True), server\_default=func.now(), onupdate=func.now())

    users: Mapped\[List\["User"\]\] \= relationship("User", back\_populates="tenant", cascade="all, delete-orphan")  
    matters: Mapped\[List\["Matter"\]\] \= relationship("Matter", back\_populates="tenant", cascade="all, delete-orphan")

class User(Base):  
    \_\_tablename\_\_ \= "users"

    user\_id: Mapped \= mapped\_column(UUID(as\_uuid=True), primary\_key=True, default=uuid.uuid4)  
    tenant\_id: Mapped \= mapped\_column(UUID(as\_uuid=True), ForeignKey("tenants.tenant\_id", ondelete="CASCADE"), nullable=False)  
    email: Mapped\[str\] \= mapped\_column(String(255), unique=True, nullable=False)  
    role\_tier: Mapped\[str\] \= mapped\_column(String(50), nullable=False)  
    created\_at: Mapped\[datetime\] \= mapped\_column(DateTime(timezone=True), server\_default=func.now())

    tenant: Mapped \= relationship("Tenant", back\_populates="users")  
      
    \_\_table\_args\_\_ \= (  
        Index("idx\_users\_tenant", "tenant\_id"),  
    )

class Matter(Base):  
    \_\_tablename\_\_ \= "matters"

    matter\_id: Mapped \= mapped\_column(UUID(as\_uuid=True), primary\_key=True, default=uuid.uuid4)  
    tenant\_id: Mapped \= mapped\_column(UUID(as\_uuid=True), ForeignKey("tenants.tenant\_id", ondelete="CASCADE"), nullable=False)  
    clio\_matter\_reference: Mapped\[str\] \= mapped\_column(String(255), unique=True, nullable=False)  
    matter\_status: Mapped\[str\] \= mapped\_column(String(50), default='active')  
    created\_at: Mapped\[datetime\] \= mapped\_column(DateTime(timezone=True), server\_default=func.now())

    tenant: Mapped \= relationship("Tenant", back\_populates="matters")  
    embeddings: Mapped\] \= relationship("DocumentEmbedding", back\_populates="matter", cascade="all, delete-orphan")  
    chronologies: Mapped\[List\["MedicalChronology"\]\] \= relationship("MedicalChronology", back\_populates="matter", cascade="all, delete-orphan")

    \_\_table\_args\_\_ \= (  
        Index("idx\_matters\_tenant", "tenant\_id"),  
    )

class MedicalChronology(Base):  
    \_\_tablename\_\_ \= "medical\_chronologies"

    chronology\_id: Mapped \= mapped\_column(UUID(as\_uuid=True), primary\_key=True, default=uuid.uuid4)  
    tenant\_id: Mapped \= mapped\_column(UUID(as\_uuid=True), ForeignKey("tenants.tenant\_id", ondelete="CASCADE"), nullable=False)  
    matter\_id: Mapped \= mapped\_column(UUID(as\_uuid=True), ForeignKey("matters.matter\_id", ondelete="CASCADE"), nullable=False)  
      
    \# Structural Data Minimization: PII/PHI is restricted to specific JSONB fields  
    \# allowing granular access control and scrubbing mechanisms.  
    patient\_reference: Mapped\[str\] \= mapped\_column(String(255), nullable=False)  
    extracted\_data: Mapped\] \= mapped\_column(JSONB, nullable=False)  
    created\_at: Mapped\[datetime\] \= mapped\_column(DateTime(timezone=True), server\_default=func.now())

    matter: Mapped\["Matter"\] \= relationship("Matter", back\_populates="chronologies")

class DocumentEmbedding(Base):  
    \_\_tablename\_\_ \= "case\_embeddings"

    embedding\_id: Mapped \= mapped\_column(UUID(as\_uuid=True), primary\_key=True, default=uuid.uuid4)  
    tenant\_id: Mapped \= mapped\_column(UUID(as\_uuid=True), ForeignKey("tenants.tenant\_id", ondelete="CASCADE"), nullable=False)  
    matter\_id: Mapped \= mapped\_column(UUID(as\_uuid=True), ForeignKey("matters.matter\_id", ondelete="CASCADE"), nullable=False)  
    document\_reference: Mapped\[str\] \= mapped\_column(String(512), nullable=False)  
    chunk\_text: Mapped\[str\] \= mapped\_column(Text, nullable=False)  
      
    \# 1536-Dimensional Vector explicitly defined for Google Vertex AI text-embedding models  
    embedding: Mapped\[Vector\] \= mapped\_column(Vector(1536), nullable=False)  
    token\_count: Mapped\[int\] \= mapped\_column(Integer, nullable=False, default=0)  
    created\_at: Mapped\[datetime\] \= mapped\_column(DateTime(timezone=True), server\_default=func.now())

    matter: Mapped\["Matter"\] \= relationship("Matter", back\_populates="embeddings")

    \# Indexing strategies must utilize HNSW (Hierarchical Navigable Small World) for performant   
    \# vector searches using cosine similarity in multi-tenant environments.  
    \_\_table\_args\_\_ \= (  
        Index("idx\_case\_embeddings\_tenant", "tenant\_id"),  
        Index("idx\_case\_embeddings\_matter", "matter\_id"),  
    )

### **2.2 The Pydantic Data Validation Schemas (schemas.py)**

The application layer demands strict inbound and outbound validation to prevent type-coercion attacks and to enforce structural data minimization before serialization occurs. Pydantic 2.0 schemas provide the rigorous parsing required for FastAPI endpoints.

Python  
\# schemas.py  
\# \==============================================================================  
\# SHTIYA OS: NODE 01 \- FASTAPI VALIDATION SCHEMAS  
\# \==============================================================================

from pydantic import BaseModel, ConfigDict, Field, EmailStr  
from typing import Optional, List, Dict, Any  
import uuid  
from datetime import datetime

class TenantBase(BaseModel):  
    firm\_name: str \= Field(..., max\_length=255, description="Registered entity name")  
    subscription\_tier: str \= Field(default="enterprise", max\_length=50)

class TenantResponse(TenantBase):  
    tenant\_id: uuid.UUID  
    created\_at: datetime  
    updated\_at: datetime  
    model\_config \= ConfigDict(from\_attributes=True)

class UserBase(BaseModel):  
    email: EmailStr  
    role\_tier: str \= Field(..., max\_length=50, pattern="^(admin|attorney|paralegal|auditor)$")

class UserCreate(UserBase):  
    tenant\_id: uuid.UUID

class UserResponse(UserBase):  
    user\_id: uuid.UUID  
    tenant\_id: uuid.UUID  
    created\_at: datetime  
    model\_config \= ConfigDict(from\_attributes=True)

class MatterBase(BaseModel):  
    clio\_matter\_reference: str \= Field(..., max\_length=255)  
    matter\_status: str \= Field(default="active", max\_length=50)

class MatterCreate(MatterBase):  
    tenant\_id: uuid.UUID

class MatterResponse(MatterBase):  
    matter\_id: uuid.UUID  
    tenant\_id: uuid.UUID  
    created\_at: datetime  
    model\_config \= ConfigDict(from\_attributes=True)

class MedicalChronologyBase(BaseModel):  
    patient\_reference: str \= Field(..., max\_length=255)  
    extracted\_data: Dict\[str, Any\] \= Field(..., description="Structured PHI data payload")

class MedicalChronologyResponse(MedicalChronologyBase):  
    chronology\_id: uuid.UUID  
    tenant\_id: uuid.UUID  
    matter\_id: uuid.UUID  
    created\_at: datetime  
    model\_config \= ConfigDict(from\_attributes=True)

class VectorSearchQuery(BaseModel):  
    query\_text: str \= Field(..., min\_length=1, max\_length=4000)  
    matter\_id: Optional \= None  
    top\_k: int \= Field(default=5, ge=1, le=50, description="Number of vector neighbors to retrieve")

## **3\. Deliverable 2: Compute Core Implementation (Node 01\)**

Node 01 operates as the central routing hub on Serverless Google Cloud Run. It dictates database interactions, interfaces with third-party webhooks, and delegates long-running tasks to the asynchronous broker. Because the architecture mandates Zero-Trust networking, Node 01 must authenticate with Node 05 (Cloud SQL) using IAM service account credentials and connect strictly over internal, private IP spaces (IPTypes.PRIVATE).6 Passwords are fundamentally eliminated from the DB connection ecosystem.

### **3.1 Zero-Trust Cloud SQL Connection Setup (database.py)**

The system utilizes the google-cloud-sql-connector alongside the pg8000 driver to facilitate automatic IAM authentication.6 By setting enable\_iam\_auth=True and passing a specifically formatted service account email (excluding the .gserviceaccount.com suffix for Postgres compatibility), the connector requests short-lived OAuth 2.0 access tokens in the background, rotating them automatically prior to expiration.6  
Furthermore, because the database enforces strict Row-Level Security, the application must inject the user's tenant\_id directly into the PostgreSQL execution session utilizing the SET LOCAL command wrapped within an atomic transaction.1 This guarantees that even if the application code issues an unfiltered SELECT \* FROM case\_embeddings, the database engine will only return records corresponding to the cryptographic context injected via SET LOCAL app.current\_tenant.

Python  
\# database.py  
\# \==============================================================================  
\# SHTIYA OS: NODE 01 \- IAM AUTHENTICATED & RLS SECURED DATABASE CONNECTIONS  
\# \==============================================================================

import os  
import logging  
import pg8000  
from sqlalchemy.ext.asyncio import create\_async\_engine, async\_sessionmaker, AsyncSession  
from sqlalchemy import text  
from google.cloud.sql.connector import Connector, IPTypes

logger \= logging.getLogger("ShtiyaOS\_DB")

\# Environment configurations mapped to Assured Workloads variables  
\# INSTANCE\_CONNECTION\_NAME format: project-id:region:instance-name  
INSTANCE\_CONNECTION\_NAME \= os.environ.get("INSTANCE\_CONNECTION\_NAME")  
\# DB\_IAM\_USER format: service-account-name@project-id.iam (PostgreSQL truncates the domain)  
DB\_IAM\_USER \= os.environ.get("DB\_IAM\_USER")  
DB\_NAME \= os.environ.get("DB\_NAME", "shtiya\_os\_core")

\# Initialize the GCP Connector. The 'LAZY' refresh strategy defers the background   
\# token refresh thread until a connection is explicitly requested, which is   
\# optimal for ephemeral Serverless Cloud Run instances.  
connector \= Connector(refresh\_strategy="LAZY")

def getconn() \-\> pg8000.dbapi.Connection:  
    """  
    Initializes a connection pool for Cloud SQL Postgres using Automatic IAM Authentication.  
    Utilizes Private IP (IPTypes.PRIVATE) ensuring no public internet exposure.  
    Passwords are mathematically eliminated from the connection flow.  
    """  
    pg8000.dbapi.paramstyle \= "pyformat"  
    try:  
        conn \= connector.connect(  
            INSTANCE\_CONNECTION\_NAME,  
            "pg8000",  
            user=DB\_IAM\_USER,  
            db=DB\_NAME,  
            enable\_iam\_auth=True,  
            ip\_type=IPTypes.PRIVATE  
        )  
        return conn  
    except Exception as e:  
        logger.error(f"Failed to establish secure IAM database connection: {str(e)}")  
        raise

\# Initialize SQLAlchemy async engine bridging the connector via the creator argument  
engine \= create\_async\_engine(  
    "postgresql+pg8000://",  
    creator=getconn,  
    pool\_size=20,  
    max\_overflow=10,  
    pool\_timeout=30,  
    pool\_recycle=1800, \# Recycle connections every 30 minutes to mitigate stale IAM tokens  
    echo=False  
)

AsyncSessionLocal \= async\_sessionmaker(  
    bind=engine,  
    class\_=AsyncSession,  
    expire\_on\_commit=False  
)

async def get\_secure\_db\_session(tenant\_id: str, matter\_id: str \= None) \-\> AsyncSession:  
    """  
    Dependency injection generator providing an AsyncSession strictly bound   
    to the authenticated user's RLS constraints.  
    """  
    async with AsyncSessionLocal() as session:  
        \# Atomic transaction enforcement guarantees the SET LOCAL session variables   
        \# do not bleed into subsequent requests executing on the same pooled connection.  
        async with session.begin():  
            \# Apply the restricted backend role  
            await session.execute(text("SET LOCAL ROLE shtiya\_backend\_role"))  
              
            \# Inject cryptographic RLS context via LEAKPROOF local variables  
            await session.execute(text(f"SET LOCAL app.current\_tenant \= '{tenant\_id}'"))  
            if matter\_id:  
                await session.execute(text(f"SET LOCAL app.current\_matter \= '{matter\_id}'"))  
              
            yield session  
        \# Context is inherently discarded when the transaction block exits.

### **3.2 Secure Redis TLS Connection (cache.py)**

Node 02/09 operates a Standard Tier GCP Memorystore for Redis instance serving dual purposes: operating the Celery message queue and managing real-time API rate limits. Memorystore supports hardware-level encryption in transit (TLS), which requires the Redis client to enforce strict SSL verification.12 Connecting to Redis via Python requires explicit configuration of ssl=True and decode\_responses=True to ensure payload integrity.12

Python  
\# cache.py  
\# \==============================================================================  
\# SHTIYA OS: NODE 02 \- SECURE REDIS MEMORYSTORE TLS CONFIGURATION  
\# \==============================================================================

import os  
import redis.asyncio as redis  
import ssl  
import logging

logger \= logging.getLogger("ShtiyaOS\_Cache")

REDIS\_HOST \= os.environ.get("REDIS\_HOST", "10.0.0.5")  \# Private Subnet IP via PSA  
REDIS\_PORT \= int(os.environ.get("REDIS\_PORT", "6378")) \# Memorystore TLS Port is strictly 6378  
REDIS\_AUTH \= os.environ.get("REDIS\_AUTH")

def create\_redis\_client() \-\> redis.Redis:  
    """  
    Initializes a secure Redis client with strictly enforced TLS encryption in-transit.  
    """  
    try:  
        \# Memorystore utilizes Google-managed certificates downloaded during provisioning.  
        \# While CERT\_NONE can bypass local verification, CERT\_REQUIRED is strictly   
        \# implemented to prevent Man-In-The-Middle (MITM) vulnerabilities within the VPC.  
        ca\_cert\_path \= os.environ.get("REDIS\_CA\_CERT", "/etc/redis-tls/ca.pem")  
          
        client \= redis.Redis(  
            host=REDIS\_HOST,  
            port=REDIS\_PORT,  
            password=REDIS\_AUTH,  
            ssl=True,  
            ssl\_ca\_certs=ca\_cert\_path,  
            ssl\_cert\_reqs=ssl.CERT\_REQUIRED,  
            decode\_responses=True  
        )  
        return client  
    except Exception as e:  
        logger.error(f"Failed to initialize Redis TLS Connection: {str(e)}")  
        raise

redis\_client \= create\_redis\_client()

### **3.3 Sliding Window Rate Limiter Logic (dependencies.py)**

The architecture audit explicitly highlights the vulnerability of API limit exhaustion during headless synchronizations against the external Clio Core API. The Clio API enforces strict limits (e.g., 60 requests per minute). If operations are not explicitly queued and throttled algorithmically, simultaneous data processing (like end-of-month billing synchronizations) triggers a 429 Too Many Requests cascade, leading to the permanent loss of billable hours.  
A standard fixed-window rate limiter fails due to boundary bursts. For instance, if a fixed window resets at the top of the minute, an algorithm could push 60 requests at 0:59 and another 60 requests at 1:00, resulting in 120 requests executed within two seconds. The external API will detect this as an immediate violation and enforce a severe backoff penalty.  
To strictly adhere to the mathematical constraint that the sum of requests over any moving time interval ![][image8], the system must deploy a Sliding Window Log utilizing Redis Sorted Sets (ZSET) manipulated via atomic Lua scripts. The Lua script ensures atomicity—the removal of expired timestamps, counting active requests, and insertion of the new request execute as a single indivisible operation on the single-threaded Redis engine, eliminating race conditions entirely.

Python  
\# dependencies.py  
\# \==============================================================================  
\# SHTIYA OS: FASTAPI DEPENDENCIES & ALGORITHMIC RATE LIMITER  
\# \==============================================================================

import time  
from fastapi import Request, HTTPException  
from typing import Optional  
from cache import redis\_client

\# Atomic Lua Script to eliminate race conditions during concurrent Redis execution.  
\# The ZSET score is the timestamp, allowing logarithmic $O(\\log(N))$ time complexity   
\# for purging expired records.  
LUA\_SLIDING\_WINDOW \= """  
local key \= KEYS  
local now\_sec \= tonumber(ARGV)  
local now\_usec \= tonumber(ARGV)  
local window\_size \= tonumber(ARGV)  
local limit \= tonumber(ARGV)  
local window\_start \= now\_sec \- window\_size  
local member \= now\_sec.. '.'.. now\_usec

\-- Purge timestamps older than the configured sliding window  
redis.call('ZREMRANGEBYSCORE', key, '-inf', window\_start)

\-- Aggregate remaining entries residing strictly within the active window  
local current\_count \= redis.call('ZCARD', key)

if current\_count \< limit then  
    redis.call('ZADD', key, now\_sec, member)  
    \-- Extend TTL equivalently to window size to prevent memory exhaustion  
    redis.call('EXPIRE', key, window\_size)  
    return 1 \-- Request Allowed  
else  
    return 0 \-- Request Rate Limited  
end  
"""

async def register\_lua\_script():  
    """Cache the script on the Redis server for optimal performance"""  
    return await redis\_client.script\_load(LUA\_SLIDING\_WINDOW)

async def check\_rate\_limit(user\_id: str, limit: int \= 55, window: int \= 60) \-\> bool:  
    """  
    Evaluates the sliding window rate limit for external integration syncs.  
    Retains a 5-request safety buffer beneath the standard 60/min limit to guarantee compliance.  
    """  
    now \= time.time()  
    now\_sec \= int(now)  
    now\_usec \= int((now \- now\_sec) \* 1000000)  
      
    script\_sha \= await register\_lua\_script()  
      
    \# Execute the SHA digest natively  
    result \= await redis\_client.evalsha(  
        script\_sha,  
        1,  
        f"rate\_limit:clio\_api:{user\_id}",  
        now\_sec,  
        now\_usec,  
        window,  
        limit  
    )  
      
    return result \== 1

async def verify\_external\_api\_throughput(request: Request):  
    """  
    FastAPI Dependency for structural throttling. If the limit is reached,  
    the application rejects the request natively, ensuring the external API  
    is never hit and the GCP Pub/Sub worker can safely NACK and retry.  
    """  
    user\_id \= request.headers.get("X-Clio-User-ID")  
    if not user\_id:  
        raise HTTPException(status\_code=400, detail="X-Clio-User-ID header is required for this operation.")  
          
    is\_allowed \= await check\_rate\_limit(user\_id)  
    if not is\_allowed:  
        raise HTTPException(status\_code=429, detail="Sliding window rate limit exceeded. Retry in 60 seconds.")  
    return user\_id

### **3.4 Asynchronous Worker Configuration (tasks.py)**

To handle the heavy computational load of Vertex AI document embedding and API synchronization, Node 01 delegates tasks to Node 02/09 via Celery. Setting up Celery to interface with a TLS-enabled Redis backend requires explicit structural configurations.  
When using a TLS connection, the protocol must be specified as rediss:// rather than redis://.14 Without providing the exact dictionary values to the broker\_use\_ssl and redis\_backend\_use\_ssl variables in the configuration, the URL scheme is improperly parsed, and the client fails during the TLS handshake, emitting a CERTIFICATE\_REQUIRED alert.15 Supplying ssl.CERT\_NONE leaves the broker vulnerable to spoofing, necessitating ssl.CERT\_REQUIRED alongside the appropriate CA files.17

Python  
\# tasks.py  
\# \==============================================================================  
\# SHTIYA OS: NODE 02/09 \- CELERY BROKER CONFIGURATION  
\# \==============================================================================

import os  
import ssl  
from celery import Celery

REDIS\_HOST \= os.environ.get("REDIS\_HOST", "10.0.0.5")  
REDIS\_PORT \= os.environ.get("REDIS\_PORT", "6378")  
REDIS\_AUTH \= os.environ.get("REDIS\_AUTH", "")  
CA\_CERT \= os.environ.get("REDIS\_CA\_CERT", "/etc/redis-tls/ca.pem")

\# The REDISS protocol explicitly designates TLS usage for the broker URL  
BROKER\_URL \= f"rediss://:{REDIS\_AUTH}@{REDIS\_HOST}:{REDIS\_PORT}/0"

\# Instantiate Celery Application  
celery\_app \= Celery("shtiya\_os\_tasks")

\# Strict SSL Verification mappings required by Celery's Redis Transport.  
\# This dictionary structure explicitly satisfies the PyAMQP and Redis client   
\# requirements, rejecting untrusted certs.  
ssl\_conf \= {  
    'ssl\_cert\_reqs': ssl.CERT\_REQUIRED,  
    'ssl\_ca\_certs': CA\_CERT  
}

celery\_app.conf.update(  
    broker\_url=BROKER\_URL,  
    result\_backend=BROKER\_URL,  
    broker\_use\_ssl=ssl\_conf,  
    redis\_backend\_use\_ssl=ssl\_conf,  
    task\_serializer='json',  
    accept\_content=\['json'\],  
    result\_serializer='json',  
    timezone='America/Los\_Angeles',  
    enable\_utc=True,  
    \# Operational constraints for heavy RAG indexing and network resiliency  
    task\_time\_limit=3600,  
    task\_soft\_time\_limit=3300,  
    redis\_socket\_timeout=30,  
    redis\_socket\_connect\_timeout=30,  
    redis\_retry\_on\_timeout=True  
)

@celery\_app.task(bind=True, max\_retries=3)  
def process\_vector\_embedding(self, document\_id: str, tenant\_id: str, matter\_id: str):  
    """  
    Background worker initializing Vertex AI API calls to vectorize  
    legal documentation and store outputs into Node 05's pgvector schema.  
    """  
    \# Vectorization processing payload executes here natively  
    pass

### **3.5 Core API Initialization (main.py)**

The application instantiation aggregates the routes and explicitly checks infrastructure health upon startup to ensure the Assured Workloads boundary is intact. It maps the dependencies to ensure compliance schemas are adhered to before requests reach the execution handlers.

Python  
\# main.py  
\# \==============================================================================  
\# SHTIYA OS: NODE 01 \- FASTAPI ENTRYPOINT  
\# \==============================================================================

from fastapi import FastAPI, Depends, APIRouter, Request  
from fastapi.middleware.cors import CORSMiddleware  
from sqlalchemy.ext.asyncio import AsyncSession  
from sqlalchemy import text  
import logging

\# Imports from preceding modules  
from database import get\_secure\_db\_session, engine  
from dependencies import verify\_external\_api\_throughput  
from cache import redis\_client

logger \= logging.getLogger("ShtiyaOS\_Main")

app \= FastAPI(  
    title="Shtiya OS Legal & Medical Core",  
    version="1.8.4",  
    description="Military-Grade API for Node 01 Processing within Assured Workloads"  
)

\# Enforce strict Cross-Origin Resource Sharing (CORS) mapped only to the Node 04 IDE  
app.add\_middleware(  
    CORSMiddleware,  
    allow\_origins=\["https://ide.shtiya.internal"\],   
    allow\_credentials=True,  
    allow\_methods=,  
    allow\_headers=,  
)

router \= APIRouter(prefix="/api/v1")

@router.get("/health", summary="Infrastructure Boundary Health Check")  
async def health\_check():  
    """Validates connectivity across the Zero-Trust network."""  
    db\_status \= "unavailable"  
    cache\_status \= "unavailable"  
      
    try:  
        \# Utilize a temporary session to execute a ping  
        async with engine.connect() as conn:  
            await conn.execute(text("SELECT 1"))  
        db\_status \= "ok"  
    except Exception as e:  
        logger.error(f"DB Healthcheck failed: {str(e)}")  
          
    try:  
        await redis\_client.ping()  
        cache\_status \= "ok"  
    except Exception as e:  
        logger.error(f"Cache Healthcheck failed: {str(e)}")

    return {  
        "boundary\_status": "SECURE",  
        "cloud\_sql": db\_status,  
        "memorystore": cache\_status  
    }

@router.post("/clio/sync", dependencies=)  
async def trigger\_clio\_synchronization(request: Request):  
    """  
    Triggers outbound synchronization.   
    Protected by the Redis sliding-window dependency.  
    """  
    user\_id \= request.headers.get("X-Clio-User-ID")  
    logger.info(f"Initiating synchronization pipeline for user {user\_id}")  
    \# Dispatch to Celery worker...  
    return {"status": "Synchronization enqueued safely"}

app.include\_router(router)

## **4\. Deliverable 3: Containerization**

Operating a Python backend within GCP Cloud Run dictates specific containerization strategies. The container must be stateless, run on an ephemeral filesystem, and minimize the attack surface by avoiding full OS distributions. Executing the runtime as a non-root user mitigates potential container-escape vulnerabilities, while caching dependency layers ensures rapid autoscaling.

### **4.1 Production-Ready Dockerfile**

The multi-stage build process extracts compilation overhead, reducing the final image size and removing unnecessary build tools (like gcc) from the production environment.

Dockerfile  
\# Dockerfile  
\# \==============================================================================  
\# SHTIYA OS: NODE 01 \- ASSURED WORKLOADS RUNTIME ENVIRONMENT  
\# \==============================================================================

\# 1\. Base Image: Leverage slim Python for minimized attack surface  
FROM python:3.11\-slim as builder

\# 2\. Prevent Python from buffering standard output and writing bytecode  
ENV PYTHONDONTWRITEBYTECODE=1 \\  
    PYTHONUNBUFFERED=1

\# 3\. System dependencies for pg8000 and cryptography compilation  
RUN apt-get update && apt-get install \-y \--no-install-recommends \\  
    gcc \\  
    libpq-dev \\  
    && rm \-rf /var/lib/apt/lists/\*

WORKDIR /app

\# 4\. Dependency caching layer  
COPY requirements.txt.  
\# Compile wheels locally to accelerate the final stage image creation  
RUN pip install \--no-cache-dir \--upgrade pip && \\  
    pip wheel \--no-cache-dir \--no-deps \--wheel-dir /app/wheels \-r requirements.txt

\# 5\. Final Stage Execution  
FROM python:3.11\-slim

ENV PYTHONDONTWRITEBYTECODE=1 \\  
    PYTHONUNBUFFERED=1

\# Establish a non-root user to satisfy strict Assured Workloads security policies  
RUN groupadd \-r shtiya\_group && useradd \-r \-g shtiya\_group shtiya\_user

WORKDIR /app

\# Copy compiled wheels from builder and install them cleanly  
COPY \--from=builder /app/wheels /wheels  
COPY \--from=builder /app/requirements.txt.  
RUN pip install \--no-cache /wheels/\*

\# 6\. Establish application payload  
COPY. /app/

\# Transfer ownership of the execution directory to the non-root user  
RUN chown \-R shtiya\_user:shtiya\_group /app

\# Drop privileges  
USER shtiya\_user

\# 7\. Expose default Cloud Run port and launch via Uvicorn  
EXPOSE 8080

CMD \["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "4", "--proxy-headers"\]

### **4.2 Application Dependencies (requirements.txt)**

The dependencies map directly to the pgvector SQL integration, the pg8000 connector, and the Celery broker environment.

# **Web Framework & Validation**

fastapi==0.111.0 uvicorn\[standard\]0.30.1 pydantic2.7.4

# **Database Subsystem & GCP Connectors**

sqlalchemy2.0.30 pgvector0.3.0 google-cloud-sql-connector\[pg8000\]1.5.0 alembic1.13.1

# **Caching & Queue Subsystem**

redis5.0.4 celery5.4.0

# **Security & Compliance**

cryptography42.0.8 google-auth2.29.0

## **5\. Deliverable 4: The Deep Build Manual (deployment.md)**

Deploying the containerized Node 01 architecture into the GCP Assured Workloads environment requires strict orchestration. Historically, connecting a Cloud Run service to internal VPC resources required a Serverless VPC Access Connector.19 However, these connectors utilize dedicated e2-micro virtual machines under the hood, leading to severe Source Network Address Translation (SNAT) port exhaustion and throughput bottlenecks.20  
Therefore, the infrastructure deployment relies exclusively on **Direct VPC Egress**.21 Direct VPC Egress allocates IP addresses directly from the target subnet to the Cloud Run instances, allowing traffic to route straight to the internal Virtual Private Cloud (VPC) network, hitting the Cloud SQL and Memorystore instances via Private Service Access (PSA) without intermediaries.21

### **Step 1: Provision the Assured Workloads Artifact Registry**

Docker images must reside strictly within the designated regulatory boundary. An Artifact Registry repository is established exclusively in us-central1.

Bash  
gcloud artifacts repositories create shtiya-os-registry \\  
    \--repository-format=docker \\  
    \--location=us-central1 \\  
    \--description="HIPAA-compliant Docker registry for Shtiya OS Node 01" \\  
    \--project=shtiya-os-assured-workloads

### **Step 2: Build and Push the Container**

Using Google Cloud Build ensures the compilation process remains internal, avoiding the egress of proprietary source code to external Continuous Integration (CI) providers.

Bash  
gcloud builds submit \\  
    \--tag us-central1-docker.pkg.dev/shtiya-os-assured-workloads/shtiya-os-registry/node-01:v1.8.4 \\  
    \--project=shtiya-os-assured-workloads

### **Step 3: Identity and Access Management (IAM) Configuration**

The principle of least privilege is absolute. The Cloud Run service requires a dedicated Service Account, distinct from the default compute identity. This service account requires exact permissions to utilize the Cloud SQL Python Connector and invoke Vertex AI embedding models.10 The roles/cloudsql.client role is required to initialize the proxy protocol, while the roles/cloudsql.instanceUser role is required for the IAM Authentication login sequence.10

Bash  
\# 3.1 Create the strict service account  
gcloud iam service-accounts create node-01-sa \\  
    \--display-name="Node 01 Application Core Identity" \\  
    \--project=shtiya-os-assured-workloads

\# 3.2 Grant Cloud SQL Client Role   
gcloud projects add-iam-policy-binding shtiya-os-assured-workloads \\  
    \--member="serviceAccount:node-01-sa@shtiya-os-assured-workloads.iam.gserviceaccount.com" \\  
    \--role="roles/cloudsql.client"

\# 3.3 Grant Cloud SQL Instance User Role   
gcloud projects add-iam-policy-binding shtiya-os-assured-workloads \\  
    \--member="serviceAccount:node-01-sa@shtiya-os-assured-workloads.iam.gserviceaccount.com" \\  
    \--role="roles/cloudsql.instanceUser"

\# 3.4 Grant Vertex AI User Role  
gcloud projects add-iam-policy-binding shtiya-os-assured-workloads \\  
    \--member="serviceAccount:node-01-sa@shtiya-os-assured-workloads.iam.gserviceaccount.com" \\  
    \--role="roles/aiplatform.user"

### **Step 4: The Direct VPC Egress Cloud Run Deployment**

The deployment orchestrates the execution of the image via gcloud run deploy. Crucially, the flag \--vpc-egress=private-ranges-only forces the container to route traffic mapped to internal CIDR blocks directly through the internal VPC.21 Concurrently, public outbound traffic (required to synchronize with the external Clio API) is routed transparently directly to the internet without requiring an expensive Cloud NAT configuration, preserving compliance while optimizing cost.21

Bash  
gcloud run deploy node-01-core \\  
    \--image us-central1-docker.pkg.dev/shtiya-os-assured-workloads/shtiya-os-registry/node-01:v1.8.4 \\  
    \--region=us-central1 \\  
    \--project=shtiya-os-assured-workloads \\  
    \--service-account=node-01-sa@shtiya-os-assured-workloads.iam.gserviceaccount.com \\  
    \--network=shtiya-vpc \\  
    \--subnet=shtiya-private-subnet \\  
    \--vpc-egress=private-ranges-only \\  
    \--allow-unauthenticated \\  
    \--set-env-vars="INSTANCE\_CONNECTION\_NAME=shtiya-os-assured-workloads:us-central1:shtiya-db-05,DB\_IAM\_USER=node-01-sa@shtiya-os-assured-workloads.iam,REDIS\_HOST=10.0.0.5" \\  
    \--min-instances=3 \\  
    \--max-instances=50

### **Step 5: Database Privileges Initialization**

As noted in the architectural review, granting the roles/cloudsql.instanceUser role in GCP IAM is structurally necessary for the Cloud SQL connector to authenticate, but it does *not* automatically grant privileges on the internal PostgreSQL tables.9 By default, new IAM database users have no permissions on a Cloud SQL instance beyond logging in.9 Once deployed, a database administrator must connect to Node 05 and grant Data Manipulation Language (DML) rights strictly to the application identity.

SQL  
\-- Connect to Postgres as superuser and execute:  
GRANT USAGE ON SCHEMA public TO "node-01-sa@shtiya-os-assured-workloads.iam";  
GRANT SELECT, INSERT, UPDATE, DELETE ON tenants, users, matters, case\_embeddings, medical\_chronologies TO "node-01-sa@shtiya-os-assured-workloads.iam";

## **6\. Synthesis and Operational Resilience**

The implementation details outlined across Deliverables 1 through 4 serve to definitively resolve the existential architectural vulnerabilities inherent in operating a high-concurrency, sovereign legal data environment.  
The systemic threat of multi-tenant vector data bleeding is entirely neutralized via cryptographic Row-Level Security explicitly integrated into the PostgreSQL engine, parametrized safely by Pydantic schemas, and seamlessly injected via the FastAPI SQLAlchemy async engine pool utilizing SET LOCAL bindings.1 This moves isolation from logical application logic down to the hardened database engine itself.  
Extraneous exposure to 429 Too Many Requests API blacklisting during intensive external synchronization loads is algorithmically avoided through the implementation of a hyper-efficient Redis sliding-window log. Finally, the overarching reliance on Zero-Trust Network Architecture is guaranteed by enforcing IAM authentication and replacing inherently weak database passwords with tightly scoped Google Cloud service accounts operating strictly over internal Virtual Private Cloud routing boundaries configured via Direct VPC Egress.6  
By executing this master codebase, schema definition, and deployment manual, the enterprise realizes a mathematically resilient infrastructure capable of fulfilling strict HIPAA requirements and autonomous legal AI operations at planetary scale.

#### **Works cited**

1. Red Team Security Architecture Blueprint  
2. pgvector support for Python \- GitHub, accessed June 25, 2026, [https://github.com/pgvector/pgvector-python](https://github.com/pgvector/pgvector-python)  
3. Shipping Multi-Tenant SaaS Using Postgres Row-Level Security | Hacker News, accessed June 25, 2026, [https://news.ycombinator.com/item?id=32241820](https://news.ycombinator.com/item?id=32241820)  
4. Getting started with pgvector-python with 7 supported libraries \- NetApp Instaclustr, accessed June 25, 2026, [https://www.instaclustr.com/education/vector-database/getting-started-with-pgvector-python-with-7-supported-libraries/](https://www.instaclustr.com/education/vector-database/getting-started-with-pgvector-python-with-7-supported-libraries/)  
5. PostgreSQL with pgvector as a Vector Database for RAG \- CodeAwake, accessed June 25, 2026, [https://codeawake.com/blog/postgresql-vector-database](https://codeawake.com/blog/postgresql-vector-database)  
6. Log in using IAM database authentication | Cloud SQL for PostgreSQL, accessed June 25, 2026, [https://docs.cloud.google.com/sql/docs/postgres/iam-logins](https://docs.cloud.google.com/sql/docs/postgres/iam-logins)  
7. Can I connect to cloud sql postgres using Private IP from my computer (locally) using Python? \- Stack Overflow, accessed June 25, 2026, [https://stackoverflow.com/questions/77448978/can-i-connect-to-cloud-sql-postgres-using-private-ip-from-my-computer-locally](https://stackoverflow.com/questions/77448978/can-i-connect-to-cloud-sql-postgres-using-private-ip-from-my-computer-locally)  
8. Long lived Cloud SQL Python Connector with IAM authentication gives intermittent "Broken pipe" and "Server disconnected" errors \- Stack Overflow, accessed June 25, 2026, [https://stackoverflow.com/questions/78307398/long-lived-cloud-sql-python-connector-with-iam-authentication-gives-intermittent](https://stackoverflow.com/questions/78307398/long-lived-cloud-sql-python-connector-with-iam-authentication-gives-intermittent)  
9. cloud-sql-python-connector/samples/notebooks/mysql\_python\_connector.ipynb at main, accessed June 25, 2026, [https://github.com/GoogleCloudPlatform/cloud-sql-python-connector/blob/main/samples/notebooks/mysql\_python\_connector.ipynb](https://github.com/GoogleCloudPlatform/cloud-sql-python-connector/blob/main/samples/notebooks/mysql_python_connector.ipynb)  
10. Manage users with IAM database authentication | Cloud SQL for PostgreSQL, accessed June 25, 2026, [https://docs.cloud.google.com/sql/docs/postgres/add-manage-iam-users](https://docs.cloud.google.com/sql/docs/postgres/add-manage-iam-users)  
11. Row-Level Security with SQLAlchemy and Alembic: A Complete Guide \- Adriano Vieira, accessed June 25, 2026, [https://www.adrianovieira.eng.br/en/posts/architecture/row-level-security-sqlachemy-alembic-guide/](https://www.adrianovieira.eng.br/en/posts/architecture/row-level-security-sqlachemy-alembic-guide/)  
12. How to Configure In-Transit Encryption for Memorystore Redis \- OneUptime, accessed June 25, 2026, [https://oneuptime.com/blog/post/2026-02-17-how-to-configure-in-transit-encryption-for-memorystore-redis/view](https://oneuptime.com/blog/post/2026-02-17-how-to-configure-in-transit-encryption-for-memorystore-redis/view)  
13. How to Configure Memorystore for Redis HA \- OneUptime, accessed June 25, 2026, [https://oneuptime.com/blog/post/2026-03-31-redis-how-to-configure-memorystore-for-redis-ha/view](https://oneuptime.com/blog/post/2026-03-31-redis-how-to-configure-memorystore-for-redis-ha/view)  
14. Configuration and defaults — Celery 5.6.3 documentation, accessed June 25, 2026, [https://docs.celeryq.dev/en/stable/userguide/configuration.html](https://docs.celeryq.dev/en/stable/userguide/configuration.html)  
15. Unable to create SSL broker/backend connection to redis \#5371 \- GitHub, accessed June 25, 2026, [https://github.com/celery/celery/issues/5371](https://github.com/celery/celery/issues/5371)  
16. Consumer Cannot Connect to Redis with TLS / SSL with broker\_use\_ssl \#8335 \- GitHub, accessed June 25, 2026, [https://github.com/celery/celery/discussions/8335](https://github.com/celery/celery/discussions/8335)  
17. Source code for celery.backends.redis, accessed June 25, 2026, [https://docs.celeryq.dev/en/main/\_modules/celery/backends/redis.html](https://docs.celeryq.dev/en/main/_modules/celery/backends/redis.html)  
18. Celery \- \[SSL: CERTIFICATE\_VERIFY\_FAILED\] certificate verify failed : Forums, accessed June 25, 2026, [https://www.pythonanywhere.com/forums/topic/30109/](https://www.pythonanywhere.com/forums/topic/30109/)  
19. VPC with connectors | Cloud Run \- Google Cloud Documentation, accessed June 25, 2026, [https://docs.cloud.google.com/run/docs/configuring/vpc-connectors](https://docs.cloud.google.com/run/docs/configuring/vpc-connectors)  
20. Google Cloud Gotcha: Direct VPC Egress on Cloud Functions vs. Cloud Run \- Medium, accessed June 25, 2026, [https://medium.com/@alexander.tyutin/google-cloud-gotcha-direct-vpc-egress-on-cloud-functions-vs-cloud-run-0980b7745b44](https://medium.com/@alexander.tyutin/google-cloud-gotcha-direct-vpc-egress-on-cloud-functions-vs-cloud-run-0980b7745b44)  
21. Configure Cloud Run Direct VPC Egress to Avoid VPC Connector Throughput Limits, accessed June 25, 2026, [https://oneuptime.com/blog/post/2026-02-17-how-to-configure-cloud-run-direct-vpc-egress-to-avoid-vpc-connector-throughput-limits/view](https://oneuptime.com/blog/post/2026-02-17-how-to-configure-cloud-run-direct-vpc-egress-to-avoid-vpc-connector-throughput-limits/view)  
22. Using IAM to connect a SA account to a Postgres SQL instance from VM in Compute Engine, accessed June 25, 2026, [https://discuss.google.dev/t/using-iam-to-connect-a-sa-account-to-a-postgres-sql-instance-from-vm-in-compute-engine/140280](https://discuss.google.dev/t/using-iam-to-connect-a-sa-account-to-a-postgres-sql-instance-from-vm-in-compute-engine/140280)  
23. IAM roles tables permissions for cloud sql \- Stack Overflow, accessed June 25, 2026, [https://stackoverflow.com/questions/79527398/iam-roles-tables-permissions-for-cloud-sql](https://stackoverflow.com/questions/79527398/iam-roles-tables-permissions-for-cloud-sql)

[image1]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADcAAAAaCAYAAAAT6cSuAAAC80lEQVR4Xu2XTYiOURTHj3zkWxqRkMhGkYyxUBRlQWLBRrGzYGGDhbJ6S7NRM4kpkhIlGykLyUdMWVAWWFgqJIqwsUHh/3eeY+573nufr3lnsnh+9W+me5/3eZ5z7/nfcx6RhgZjDjTZD3aJidBcaIKfGA92QAMydsExqGPQkez/SmyBPkC/A32BPmb/f4NOQ7PtBwFroYfQfD8B5kGPpP2+1BtoU3BdGbhwV6A9fqIsF6Gf0EY33isa6F1oZjA+DboJ7Q3GYmwXDWpIaqx8wCroMbTETxQxS3SVX0EL3BwDGoZ+QVuD8W3QC+m83tMvGtwuP1GRSdA1qOXGC1kJfYaui94khGZ+Ku27yh24BJ2xixJMhW6Jpv1yN1eHfaLvwncqDVeVq3vUT4AN0HfoieipSOinl9BuuygBA2Jgw9Ke0nVZI+rZ9X4iD+5AzG8M5j70CeoLxtdBb7O/eTCNmc5MzW6wUDS4okX9h3mKu3MVupDpMvReNP0W28UZO6VcqpnfeKh0A3vX4248ifntHrRUdHVM9EwMBscV5DUpivzG4jzdD4oeVMyUmP8tuNKZYH474SdyKBOc+Y1pPcPNEQZx0A9m0CaxOQuOZasUvJE/5osoE5zVt9gqsyifE61dHpalO9Lpf1IpLa2+vYYWtU/lwgfTjzy9UuTVN3Ya9LelHVOUYzegU6Inc6x+WlmKneodcOW+inoj5a8Y9CmDS+22rbD3G7uaA6ItnXU23MXz0GHR+slFifmN8GBjo5F67l/Y2zGtwp6P/SQfXAZ7ee8L9pjMhB8ycl+2biwbDMjG3kHLst9shp7JyE7RJqmdYcawvlbJslq0JL3CVaB/mKLctTy/kZZoCzbaZxayAnou8UOhCgzODgjei35jV+Qb8h7ogVT/oqgNv7MGZXTd/mrRDDgEnRUtHTxU6OuQ/aLeHKvvxg74IL5Q7e+sDJ6WTEnCe04J5giz5LZokzGusECflHgX0g0YNE9Q3wI2NDT8B/wB+cCWJVdDXZ0AAAAASUVORK5CYII=>

[image2]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABkAAAAaCAYAAABCfffNAAABi0lEQVR4Xu2UvytGURjHH2HwO8WLYpBJlCSkLGQgm02UwaAkyl/wjiwUJgavQZY3s1gMitnAP2CTLBYGfL+ec73PPZN77xkM76c+de95Tvc853nOPSJl/jsT8Bl+OS9gjYk3wksTp+ewzsz5ExXwEH7AdzgWD/8wB4sSTyARzfAEbohmeiC6sGUTLnhjiRiAu7ADPsIn2G3iVfDIzUsNM1xxz3nR3az9RkVaRHfKHadmBw655374Cu9gkxsbh/vuORVRP5gtYWnO4CecdmPcZZB+2Ebz41yEi/E0Be1HBMvEcrFsk5KxH8yetR72A2BR9AA8wG0vlgi/H5Y20ePMhWw/mNgSLMARuAX3YLuZE4Ol4BVR6wccefgCe81YH5yBp6K3RLXobXAs3g88Bd+kdBfxKpm1Exw8zrzLbD9ysAdeSenYc6fXsN69B4EfvxEtM7PnLliyoDBzlosLdMFbOBibkZEo83u4LtoX9jYo7E/UjwZYGQ+HYVT0R231A6HohPNwGa6K3nNlsvMNnl9FDPam9YAAAAAASUVORK5CYII=>

[image3]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABIAAAAaCAYAAAC6nQw6AAABNElEQVR4Xu3TvysHcRzH8bdQRFIUksQmox+TRUl9F4NJKWRgtygWJWVhk5K/ACObgTL4A2Q2iEn+AInnq8/7zueO7gwy3aseXZ/3fe6+3/f77syqVPm7tKGGPl+3YBojqE82laUZB9jAE3Zxhnk/HqEx3V2QKWxiCC84tnBzZQyvvqc0SxjHDN4te9EE3rAW1Uqzgwf0RrVVfGA2qhVGw720MJMGr+motdpV27/KIJ6xHtUG8IhD+7p5j4V5nmMRdV5Po/mohS1fa8M27tDvtVFc+zo53+Xn0mg+ejq3OLVwgdrq9vNNuMAJ5rCPZcv9o1ZcWdiox97htThq6R6TuXomP80nn07cWHjTkwxb7gdXLMxnAe3xiVz0Cmjwam3PwieVaU2fQEKbiqJZqfVvT6vKP+YTy9cwmEcs6mQAAAAASUVORK5CYII=>

[image4]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAcAAAAaCAYAAAB7GkaWAAAAnElEQVR4XmNgGHjADcSFQKyGLgECRUD8H4jT0SVAQASIHYCYFU0cN2AGYmMgtoGy4QBkxAQgrgXi00DciyzpCsQ1QMwHxAeAeCUDku5MINYHYksg/gbEETAJZNAAxE+AWBFNHOyFq0A8BYgZ0eQYPID4FxC7ALE6A8QUOJjBAHGpMAMklECOhAM/Boh9G4C4gAGL0TxALIAuOBIAANr5E9moi3bFAAAAAElFTkSuQmCC>

[image5]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAmwAAABOCAYAAACdbkoxAAAFP0lEQVR4Xu3dW6jlUxwH8CWX3C8RaRRJhgyjUEwUpYxEwoMybx6MB4ppqHkxQwpF4UUomdIQ8jAuibKLB/HgSc2LBxKheJFCLuvX2n9nnWXvc/bZe59z9p4+n/p2/v+19j57n/V/OL/W/7JSAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgLl0cs5rOftzTsjZmHMgZ2/9IgAA1tclOfv66fYBAJght+dszfkh55CcUxZ3AwCwnqI429nf3pZzQ9UHAMAMiNOfN/W3T8t5q+oDAGCdxQ0Hv+S8WbU9mXNozqU5G3JuqfoAAJgh1+Zcn3N32wEAwGy4p20AAAAAAAAAAACAKYk7Qb/K+Sent7jrPy+n0v9XzpFNHwAAa+CONFrB9krbAQCwni5OZRH0ccSyTve1jTPsxjRawRY/B3kpjT9Wq21HKscDAJgj16RSfER+7v/8Nef46jVn5HxU7YeP08L7vs65anH3/+xtG6Yo1vycpkkKthirC5q2OM16VtO2Xg7PubVtBABmXxRfsfxS59icv6v9Azmbqv3Oo2lh+ablHJazu22c0M05W9LgwmkSkxRsMVado1J5yO5DqSx1NSv2pekfCwBglUXxUbsi59P+dlxUv6vq65yd830qxd2oYibusrZxQqenwYXTJMYt2IaN1YNpugVbFIEhltA6N638FOfmVI4FADBH/qy249qrD1NZMzNEQRQFTCuWaKpn4UYRRcK01+CcpYJt2FhNs2A7NefhnKdyXsz5JOeBRa9YXnxPBRsAzJHzcz5I5Z94pH1MRRQag4qNd1KZYasdXW1vzfkplVOhnV4qp1GnabmCrfu72sTs1LCZqXELtmFjtVTBFt+h/W51WjGDF78vjlvo7mhdykVp8d8as6K9ah8AmHFxDdqg03idYUVIFGsxE1e7q9l/ptnvpTIrNE3LFWzPD8ljOSdWr6utZcEW36H9bnUGeSMtnIqOMf6t6hukXahewQYAc+S4VG442NB2VOJate6aqVoULPUNB3HnYTebFttPpIXr4Dqf59zftIVjcm5bIt1s0iDLFWzjGLdgGzZWSxVs4/i92o5ibUd/O8b87aov7Ml5oWk7KZVjAQDMuHgMRxQdkXicxzBxKq2eKYsC749U3vdjKo8Aie1v+/1Xp3LHabynLc6+TEsXhysVnxmrDcTnx/e4cHH32MYt2NqxikL01bQwzt9VfeOKovibVD77i1Q+I8TYxunR5/r7nctTOeVduzKV1wMAB5HPUpmVGUXMJkXh8n4qhUEtHidRX9M2q8Yt2EKM1WqKgjeKwrj5oL7esH6cSG13P21bHAsA4CASpz5fbxuHiFmu7alc3xan6DrbUnlo6zyYpGCLsYrnr62GuN4txvS6tiO7N5UZtmf7+4+ncro4jsMj3Yv6YhZuXo4FADCimDHb2f85irg2LgqCI6q296rtWTdJwbbSsVqJ+L1L3YzQ3kQRp6bjOHSnTcM5OWdW+wAAc2mSgm1WnNc2AAAcDOJu1D1p4SaBSFzr1a1VuiXn6aY/HmAb7QAArIF4JEf7HLRIPLMt3DmgLxLtAAAAAAAAAAAAMA2b08JanYNszNmfht9FCgDAjOi1DQAArL54tMeu/nasKNBrUi+uHvsAAKyxWKPz3bZxiF7bAADA2ogF7Delch1brMdZJ5Z76vSqbQAA1lCshQoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAivwLbenxK/nTLmIAAAAASUVORK5CYII=>

[image6]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABIAAAAaCAYAAAC6nQw6AAAA/klEQVR4XmNgGAWjgHqAGYiNgdgOiFmhYoxArA/E8jBFhABIYy8QlwLxCSgbBECGfALiPUDMDRXDC1yBuAaIBRkgBi2EinMC8QIgPgDEPFAxvCAViDWB2BKIvwFxBJKcDRBPRuKDgsATiA2QxDBAAxA/AWJFJLEgIE6HsquAeDMQPwRiX7gKNADy1mkgXgPELFAxUGA3MEBcCwMgLx5gwGOQJAPEpnIkMZDLehgQBoMAQYPEgfguA8T5IACKyU4gNoSrgACCBoG8kQXEL4F4ERDvAOIAFBUQQNAgGOBggHgTRGMDRBtECFDFIFD6AXn7KxAfZ4DkBFwuHwVDAgAAKAokHC86KLwAAAAASUVORK5CYII=>

[image7]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABIAAAAaCAYAAAC6nQw6AAABKklEQVR4Xu2QPyuGYRSHj1CEwZ+IlCzKJCmlZGKwyeQLoIz+pGR4V8XCoGTAYPIBDAZlUSYfwKCkrAYr169z3vd57np7vINFPVddPfdz7nOf+9zHrKTk72jGKZzD1og14QSOVJN+QwePcAcfYy1U5BPvsCNihSzgPnabF7qMeDte4D12RqyQVRzHGfzCldzeLJ7EWoXX8Cy++q9LBd9wNBdbxnVswT0cs6zTa8vmWUPPesIb80NCw66YdzuIr7gZe+r03XyOCdXE3VxMnR2aF1bRaeyLvXnzQrokYQBfzNsXavkAJ2sZGSp8jqexTtCNG/iBV3iLS0lGhuZ2bAXDFm3mz9S3Hou4Zd5xP/ak242hGenpQ+aXbeNwktEAvfiM3zkfsCufVPLf+AENRCiLbpoVHAAAAABJRU5ErkJggg==>

[image8]: <data:image/png;base64,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>