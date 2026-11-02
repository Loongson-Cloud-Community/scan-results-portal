from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import HTTPException
from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session, load_only, raiseload, selectinload

from ..models import SrpmScanArtifact, SrpmScanTask


def format_timestamp(value: datetime | None) -> str:
    if value is None:
        return "—"
    return value.strftime("%Y-%m-%d %H:%M:%S")


def scan_method(task: SrpmScanTask) -> str:
    metadata = task.scan_metadata or {}
    manifest = metadata.get("manifest") or {}
    scan_ini = metadata.get("scan_ini") or {}
    return manifest.get("method") or scan_ini.get("method") or "csmock"


def task_payload(task: SrpmScanTask) -> dict[str, Any]:
    return {
        "id": task.id,
        "jenkins_job_full_name": task.jenkins_job_full_name,
        "jenkins_build_number": task.jenkins_build_number,
        "package_name": task.package_name,
        "version": task.version,
        "release": task.release,
        "nvr": task.nvr,
        "srpm_name": task.srpm_name,
        "architecture": task.architecture,
        "lifecycle_state": task.lifecycle_state,
        "execution_result": task.execution_result,
        "scan_result": task.scan_result,
        "gate_result": task.gate_result,
        "jenkins_node": task.jenkins_node,
        "triggered_by": task.triggered_by,
        "scanner": task.scanner,
        "scanner_version": task.scanner_version,
        "mock_config": task.mock_config,
        "enabled_plugins": task.enabled_plugins,
        "total_findings": task.total_findings,
        "created_at": task.created_at,
        "started_at": task.started_at,
        "finished_at": task.finished_at,
        "duration_ms": task.duration_ms,
        "scan_duration_ms": task.scan_duration_ms,
        "last_synced_at": task.last_synced_at,
        "sync_status": task.sync_status,
    }


def task_filters(search: str | None, scan_result: str | None) -> list[Any]:
    filters = []
    if search:
        term = f"%{search}%"
        filters.append(or_(SrpmScanTask.srpm_name.ilike(term), SrpmScanTask.nvr.ilike(term)))
    if scan_result:
        filters.append(SrpmScanTask.scan_result == scan_result.upper())
    return filters


def detail_values(task: SrpmScanTask) -> dict[str, Any]:
    metadata = task.scan_metadata or {}
    manifest = metadata.get("manifest") or {}
    scan_ini = metadata.get("scan_ini") or {}
    srpm_name = (
        task.srpm_name
        or manifest.get("srpm_name")
        or (f"{task.nvr}.src.rpm" if task.nvr else None)
    )
    csmock_args = (
        manifest.get("csmock_args")
        or scan_ini.get("csmock_args")
        or scan_ini.get("tool-args")
        or scan_ini.get("tool_args")
    )
    args = manifest.get("args") or scan_ini.get("args")
    args_fields: list[dict[str, str]] = []
    if args:
        args_fields.append({"name": "", "value": str(args)})
    if not args:
        if task.enabled_plugins:
            args_fields.append(
                {"name": "analyzers", "value": f'"{",".join(task.enabled_plugins)}"'}
            )
        if csmock_args:
            args_fields.append({"name": "csmock_args", "value": f'"{csmock_args}"'})
        if task.mock_config:
            args_fields.append({"name": "mock_config", "value": f'"{task.mock_config}"'})
        if srpm_name:
            args_fields.append({"name": "srpm_name", "value": f'"{srpm_name}"'})
    elif csmock_args:
        args_fields.append({"name": "csmock_args", "value": f'"{csmock_args}"'})
    return {"method": scan_method(task), "args": args_fields, "srpm_name": srpm_name}


def apply_task_fields(task: SrpmScanTask, values: dict[str, Any]) -> None:
    for field, value in values.items():
        if field in {"jenkins_build_number", "jenkins_job_full_name"} or not hasattr(
            task, field
        ):
            continue
        setattr(task, field, value)


def get_artifact_task(db: Session, task_id: int) -> SrpmScanTask:
    """Read delivery metadata, including archive references, without findings."""
    task = db.scalar(
        select(SrpmScanTask)
        .options(
            load_only(
                SrpmScanTask.id,
                SrpmScanTask.jenkins_job_full_name,
                SrpmScanTask.jenkins_build_number,
                raiseload=True,
            ),
            selectinload(SrpmScanTask.artifacts).load_only(
                SrpmScanArtifact.id,
                SrpmScanArtifact.task_id,
                SrpmScanArtifact.name,
                SrpmScanArtifact.artifact_type,
                SrpmScanArtifact.relative_path,
                SrpmScanArtifact.size_bytes,
                raiseload=True,
            ),
            raiseload("*"),
        )
        .where(SrpmScanTask.id == task_id)
    )
    if task is None:
        raise HTTPException(status_code=404, detail="scan task not found")
    return task


def get_task(db: Session, task_id: int) -> SrpmScanTask:
    task = db.scalar(
        select(SrpmScanTask)
        .options(
            selectinload(SrpmScanTask.artifacts),
            selectinload(SrpmScanTask.summaries),
            selectinload(SrpmScanTask.findings),
        )
        .where(SrpmScanTask.id == task_id)
    )
    if task is None:
        raise HTTPException(status_code=404, detail="scan task not found")
    return task


def list_task_page(
    db: Session,
    search: str | None,
    scan_result: str | None,
    page: int,
    page_size: int,
) -> tuple[int, list[SrpmScanTask]]:
    filters = task_filters(search, scan_result)
    total = db.scalar(select(func.count()).select_from(SrpmScanTask).where(*filters)) or 0
    rows = db.scalars(
        select(SrpmScanTask)
        .where(*filters)
        .order_by(desc(SrpmScanTask.created_at), desc(SrpmScanTask.id))
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return total, rows
