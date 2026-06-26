# models.py
# ==============================================================================
# SHTIYA OS: NODE 05 - SECURE MULTI-TENANT ALCHEMY MODELS
# ==============================================================================

import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy import String, Integer, DateTime, ForeignKey, Text, Index
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func
from pgvector.sqlalchemy import Vector

class Base(DeclarativeBase):
    """
    Core declarative base for Shtiya OS.
    All tables are inherently prepared for PostgreSQL Row-Level Security (RLS)
    by strictly requiring a tenant_id mapping.
    """
    pass

class Tenant(Base):
    __tablename__ = "tenants"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    firm_name: Mapped[str] = mapped_column(String(255), nullable=False)
    subscription_tier: Mapped[str] = mapped_column(String(50), default='enterprise')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    users: Mapped[List["User"]] = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    matters: Mapped[List["Matter"]] = relationship("Matter", back_populates="tenant", cascade="all, delete-orphan")

class User(Base):
    __tablename__ = "users"

    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.tenant_id", ondelete="CASCADE"), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    role_tier: Mapped[str] = mapped_column(String(50), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="users")

    __table_args__ = (
        Index("idx_users_tenant", "tenant_id"),
    )

class Matter(Base):
    __tablename__ = "matters"

    matter_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.tenant_id", ondelete="CASCADE"), nullable=False)
    clio_matter_reference: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    matter_status: Mapped[str] = mapped_column(String(50), default='active')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="matters")
    embeddings: Mapped[List["DocumentEmbedding"]] = relationship("DocumentEmbedding", back_populates="matter", cascade="all, delete-orphan")
    chronologies: Mapped[List["MedicalChronology"]] = relationship("MedicalChronology", back_populates="matter", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_matters_tenant", "tenant_id"),
    )

class MedicalChronology(Base):
    __tablename__ = "medical_chronologies"

    chronology_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.tenant_id", ondelete="CASCADE"), nullable=False)
    matter_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("matters.matter_id", ondelete="CASCADE"), nullable=False)

    # Structural Data Minimization: PII/PHI is restricted to specific JSONB fields
    # allowing granular access control and scrubbing mechanisms.
    patient_reference: Mapped[str] = mapped_column(String(255), nullable=False)
    extracted_data: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    matter: Mapped["Matter"] = relationship("Matter", back_populates="chronologies")

class DocumentEmbedding(Base):
    __tablename__ = "case_embeddings"

    embedding_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.tenant_id", ondelete="CASCADE"), nullable=False)
    matter_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("matters.matter_id", ondelete="CASCADE"), nullable=False)
    document_reference: Mapped[str] = mapped_column(String(512), nullable=False)
    chunk_text: Mapped[str] = mapped_column(Text, nullable=False)

    # 1536-Dimensional Vector explicitly defined for Google Vertex AI text-embedding models
    embedding: Mapped[Vector] = mapped_column(Vector(1536), nullable=False)
    token_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    matter: Mapped["Matter"] = relationship("Matter", back_populates="embeddings")

    # Indexing strategies must utilize HNSW (Hierarchical Navigable Small World) for performant
    # vector searches using cosine similarity in multi-tenant environments.
    __table_args__ = (
        Index("idx_case_embeddings_tenant", "tenant_id"),
        Index("idx_case_embeddings_matter", "matter_id"),
    )