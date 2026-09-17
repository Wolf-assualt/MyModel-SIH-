from datetime import datetime, timezone
from enum import Enum
from typing import Generic, Optional, TypeVar
from pydantic import BaseModel, Field

T = TypeVar("T")


class AssetStatus(str, Enum):
    ACCEPTED = "ACCEPTED"
    UNDER_REVIEW = "UNDER_REVIEW"
    QUARANTINED = "QUARANTINED"
    REJECTED = "REJECTED"


class ResponseEnvelope(BaseModel, Generic[T]):
    success: bool = True
    data: Optional[T] = None
    error: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
