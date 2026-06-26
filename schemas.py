# schemas.py
# ==============================================================================
# SHTIYA OS: NODE 01 - FASTAPI VALIDATION SCHEMAS
# ==============================================================================

from pydantic import BaseModel, ConfigDict, Field, EmailStr
from typing import Optional, List, Dict, Any
import uuid
from datetime import datetime

class TenantBase(BaseModel):
    firm_name: str = Field(..., max_length=255, description="Registered entity name")
    subscription_tier: str = Field(default="enterprise", max_length=50)

class TenantResponse(TenantBase):
    tenant_id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)

class UserBase(BaseModel):
    email: EmailStr
    role_tier: str = Field(..., max_length=50, pattern="^(admin|attorney|paralegal|auditor)$")

class UserCreate(UserBase):
    tenant_id: uuid.UUID

class UserResponse(UserBase):
    user_id: uuid.UUID
    tenant_id: uuid.UUID
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class MatterBase(BaseModel):
    clio_matter_reference: str = Field(..., max_length=255)
    matter_status: str = Field(default="active", max_length=50)

class MatterCreate(MatterBase):
    tenant_id: uuid.UUID

class MatterResponse(MatterBase):
    matter_id: uuid.UUID
    tenant_id: uuid.UUID
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class MedicalChronologyBase(BaseModel):
    patient_reference: str = Field(..., max_length=255)
    extracted_data: Dict[str, Any] = Field(..., description="Structured PHI data payload")

class MedicalChronologyResponse(MedicalChronologyBase):
    chronology_id: uuid.UUID
    tenant_id: uuid.UUID
    matter_id: uuid.UUID
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class VectorSearchQuery(BaseModel):
    query_text: str = Field(..., min_length=1, max_length=4000)
    matter_id: Optional[uuid.UUID] = None
    top_k: int = Field(default=5, ge=1, le=50, description="Number of vector neighbors to retrieve")