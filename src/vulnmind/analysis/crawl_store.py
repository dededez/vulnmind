"""Persist crawl discoveries as one scan and its web_endpoints rows.

Crawl results are observations of authorized responses, not validation: a stored
endpoint only records that the method+URL appeared in fetched HTML. The caller
owns the transaction; this module never commits on its own.
"""
from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from vulnmind.persistence.models import Project, Scan
from vulnmind.persistence.repositories import WebEndpointRepository


def store_crawl_result(*, session: Session, project_id: UUID, actor: str,
                       endpoints: list[dict]) -> Scan:
    """Create a finished crawl-mode scan and store the deduplicated endpoints."""
    if not isinstance(actor, str) or not actor.strip():
        raise ValueError("actor is required")
    if session.get(Project, project_id) is None:
        raise ValueError("project is not stored")
    scan = Scan(id=uuid4(), project_id=project_id, status="finished", mode="crawl")
    session.add(scan)
    session.flush()
    WebEndpointRepository(session).replace_for_scan(scan.id, project_id, endpoints)
    return scan
