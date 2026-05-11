"""Review model."""
import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class Review(Base):
    __tablename__ = "reviews"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    pull_request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("pull_requests.id"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(50), default="pending")
    model_used: Mapped[str | None] = mapped_column(String(100), nullable=True)
    trigger_event: Mapped[str | None] = mapped_column(String(100), nullable=True)
    total_comments: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    info_count: Mapped[int] = mapped_column(Integer, default=0)
    overall_quality_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    total_lines_reviewed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    processing_time_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    inference_time_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    github_review_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    diff_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    pull_request: Mapped["PullRequest"] = relationship("PullRequest", back_populates="reviews")
    comments: Mapped[list["ReviewComment"]] = relationship(
        "ReviewComment", back_populates="review", cascade="all, delete-orphan"
    )
    quality_metrics: Mapped[list["QualityMetric"]] = relationship(
        "QualityMetric", back_populates="review", cascade="all, delete-orphan"
    )
