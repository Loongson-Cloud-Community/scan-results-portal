from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import HTTPException
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session, load_only, raiseload, selectinload

from ..models import RpmScanArtifact, RpmScanTask


def format_timestamp(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S") if value else "—"


def get_artifact_task(db: Session, task_id: int) -> RpmScanTask:
    """Read delivery metadata without loading scan results or large raw data."""
    task = db.scalar(
        select(RpmScanTask)
        .options(
            load_only(
                RpmScanTask.id,
                RpmScanTask.jenkins_job_full_name,
                RpmScanTask.jenkins_build_number,
                raiseload=True,
            ),
            selectinload(RpmScanTask.artifacts).load_only(
                RpmScanArtifact.id,
                RpmScanArtifact.task_id,
                RpmScanArtifact.name,
                RpmScanArtifact.artifact_type,
                RpmScanArtifact.relative_path,
                RpmScanArtifact.size_bytes,
                raiseload=True,
            ),
            raiseload("*"),
        )
        .where(RpmScanTask.id == task_id)
    )
    if task is None:
        raise HTTPException(status_code=404, detail="RPM scan task not found")
    return task


def get_task(db: Session, task_id: int) -> RpmScanTask:
    task = db.scalar(
        select(RpmScanTask)
        .options(
            selectinload(RpmScanTask.artifacts),
            selectinload(RpmScanTask.components),
            selectinload(RpmScanTask.vulnerabilities),
        )
        .where(RpmScanTask.id == task_id)
    )
    if task is None:
        raise HTTPException(status_code=404, detail="RPM scan task not found")
    task.artifacts.sort(key=lambda row: row.name)
    task.components.sort(key=lambda row: (row.vendor, row.product, row.version))
    task.vulnerabilities.sort(
        key=lambda row: (row.severity, row.cve_number, row.vendor, row.product)
    )
    return task


def list_task_page(
    db: Session,
    search: str | None,
    state: str | None,
    page: int,
    page_size: int,
) -> tuple[int, list[RpmScanTask]]:
    filters = []
    if search:
        filters.append(RpmScanTask.rpm_name.ilike(f"%{search}%"))
    if state:
        filters.append(RpmScanTask.state == state.upper())
    total = db.scalar(select(func.count()).select_from(RpmScanTask).where(*filters)) or 0
    rows = db.scalars(
        select(RpmScanTask)
        .where(*filters)
        .order_by(desc(RpmScanTask.created_at), desc(RpmScanTask.id))
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return total, rows


def task_payload(task: RpmScanTask) -> dict[str, Any]:
    return {
        "id": task.id,
        "scan_key": task.scan_key,
        "jenkins_job_full_name": task.jenkins_job_full_name,
        "jenkins_build_number": task.jenkins_build_number,
        "rpm_name": task.rpm_name,
        "rpm_sha256": task.rpm_sha256,
        "state": task.state,
        "scanner": task.scanner,
        "scanner_version": task.scanner_version,
        "total_vulnerabilities": task.total_vulnerabilities,
        "component_count": task.component_count,
        "critical_count": task.critical_count,
        "high_count": task.high_count,
        "medium_count": task.medium_count,
        "low_count": task.low_count,
        "unknown_count": task.unknown_count,
        "created_at": task.created_at,
        "finished_at": task.finished_at,
        "sync_status": task.sync_status,
    }
