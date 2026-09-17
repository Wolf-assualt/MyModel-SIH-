"""Analyst SOC Dashboard and Investigation Endpoints."""
from typing import List
from fastapi import APIRouter, Query

from app.dashboard.service import default_dashboard_service
from app.schemas.base import ResponseEnvelope
from app.schemas.dashboard import (
    ActivityTimelineItem,
    ContributorLeaderboardItem,
    InvestigationView,
    SystemHealthOverview,
)

router = APIRouter(prefix="/dashboard", tags=["Analyst Dashboard & SOC Workbench"])


@router.get("/overview", response_model=ResponseEnvelope[SystemHealthOverview])
def get_system_overview() -> ResponseEnvelope[SystemHealthOverview]:
    """Retrieve real-time system health metrics, asset inventory, and audit chain head."""
    overview = default_dashboard_service.get_system_overview()
    return ResponseEnvelope(data=overview)


@router.get("/timeline", response_model=ResponseEnvelope[List[ActivityTimelineItem]])
def get_activity_timeline(
    limit: int = Query(20, ge=1, le=100, description="Maximum number of historical timeline events"),
) -> ResponseEnvelope[List[ActivityTimelineItem]]:
    """Retrieve chronologically ordered activity events across all pipeline operations."""
    timeline = default_dashboard_service.get_activity_timeline(limit=limit)
    return ResponseEnvelope(data=timeline)


@router.get("/investigate/{entity_id}", response_model=ResponseEnvelope[InvestigationView])
def investigate_entity_lineage(
    entity_id: str,
) -> ResponseEnvelope[InvestigationView]:
    """Conduct deep-dive forensic audit and graph lineage traversal for an asset or contributor."""
    investigation = default_dashboard_service.investigate_entity(entity_id=entity_id)
    return ResponseEnvelope(data=investigation)


@router.get("/contributors", response_model=ResponseEnvelope[List[ContributorLeaderboardItem]])
def get_contributor_leaderboard() -> ResponseEnvelope[List[ContributorLeaderboardItem]]:
    """Retrieve dynamic contributor risk leaderboard sorted by threat score descending."""
    leaderboard = default_dashboard_service.get_contributor_leaderboard()
    return ResponseEnvelope(data=leaderboard)
