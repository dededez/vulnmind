"""Read a stored report back for a scan.

The database row is the index; the body comes from the report store and is
verified against its hash. A scan without a report row returns no content
rather than an empty document that could be mistaken for a clean result.
"""
from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vulnmind.persistence.models import Finding, Report, Scan
from vulnmind.reports.store import ReportStore


class LoadedReport(BaseModel):
    model_config = ConfigDict(frozen=True)
    scan_id: UUID
    scan_status: str
    format: str | None
    storage_uri: str | None
    content: str | None
    findings: int


def load_report(session: Session, store: ReportStore, scan_id: UUID) -> LoadedReport:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise ValueError("scan is not stored")
    if not isinstance(store, ReportStore):
        raise ValueError("a report store is required")
    row = session.scalar(select(Report).where(Report.scan_id == scan_id)
                         .order_by(Report.created_at.desc()).limit(1))
    findings = session.scalar(select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)) or 0
    if row is None:
        return LoadedReport(scan_id=scan_id, scan_status=scan.status, format=None, storage_uri=None,
                            content=None, findings=findings)
    return LoadedReport(scan_id=scan_id, scan_status=scan.status, format=row.format,
                        storage_uri=row.storage_uri, content=store.read(row.storage_uri),
                        findings=findings)
