"""QualityMetric model."""
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class QualityMetric(Base):
    __tablename__ = "quality_metrics"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    review_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("reviews.id"), nullable=False
    )
    repository_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=False
    )
    file_path: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    language: Mapped[str | None] = mapped_column(String(50), nullable=True)
    cyclomatic_complexity: Mapped[float | None] = mapped_column(Float, nullable=True)
    cognitive_complexity: Mapped[float | None] = mapped_column(Float, nullable=True)
    lines_of_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    comment_ratio: Mapped[float | None] = mapped_column(Float, nullable=True)
    duplication_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    avg_function_length: Mapped[float | None] = mapped_column(Float, nullable=True)
    max_function_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    function_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    overall_quality_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    review: Mapped["Review"] = relationship("Review", back_populates="quality_metrics")
