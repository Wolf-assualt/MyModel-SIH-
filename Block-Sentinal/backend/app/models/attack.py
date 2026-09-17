"""AttackScenario model for reproducible Red Team attack lab experiments."""
import uuid
from typing import Optional
from sqlalchemy import String, Float, Boolean, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class AttackScenario(Base, TimestampMixin):
    """Controlled Red Team attack scenario entity. Strictly isolated simulations."""
    __tablename__ = "attack_scenarios"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scenario_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    attack_class: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    
    # Must always be true to distinguish test/demo simulation from operational incident
    is_simulation: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    parameters_json: Mapped[str] = mapped_column(Text, nullable=False)
    target_asset_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target_asset_id: Mapped[str] = mapped_column(String(64), nullable=False)

    detection_status: Mapped[str] = mapped_column(String(50), default="PENDING", nullable=False)
    detection_confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    evidence_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
