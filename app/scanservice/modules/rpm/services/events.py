from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ....config import Settings
from ....jenkins import JenkinsClient
from ....scan_state import FAILED, NOT_AVAILABLE, RUNNING, accepts_event, is_terminal
from ..models import RpmScanTask
from .synchronization import sync_task


def find_task(db: Session, values: dict[str, Any]) -> RpmScanTask | None:
    return db.scalar(
        select(RpmScanTask).where(
            RpmScanTask.jenkins_job_full_name == values["jenkins_job_full_name"],
            RpmScanTask.jenkins_build_number == values["jenkins_build_number"],
            RpmScanTask.scan_key == values["scan_key"],
        )
    )


def register_start(db: Session, values: dict[str, Any]) -> RpmScanTask:
    task = find_task(db, values)
    if task is None:
        task = RpmScanTask(
            scan_key=values["scan_key"],
            jenkins_job_full_name=values["jenkins_job_full_name"],
            jenkins_build_number=values["jenkins_build_number"],
            rpm_name=values["rpm_name"],
            rpm_sha256=values["rpm_sha256"],
            state=RUNNING,
            sync_status="PENDING",
        )
        db.add(task)
    if accepts_event(task.state, "started", ended=task.finished_at is not None):
        task.created_at = (
            task.created_at or values.get("created_at") or datetime.now(timezone.utc)
        )
        task.state = RUNNING
    return task


def complete_task(
    db: Session,
    settings: Settings,
    task: RpmScanTask,
    values: dict[str, Any],
) -> RpmScanTask:
    if not accepts_event(task.state, "completed"):
        return task
    task.finished_at = (
        task.finished_at or values.get("finished_at") or datetime.now(timezone.utc)
    )
    if task.cbt_exit_code is None:
        task.cbt_exit_code = values.get("cbt_exit_code")
    task.sync_status = "PENDING"
    db.commit()

    client = JenkinsClient(
        settings.jenkins_base_url,
        settings.jenkins_user,
        settings.jenkins_token,
        settings.request_timeout_seconds,
    )
    try:
        sync_task(db, client, task, settings.artifact_limits)
        db.commit()
    except Exception as exc:
        db.rollback()
        task = find_task(db, values)
        if task is None:
            raise
        if is_terminal(task.state):
            return task
        task.state = NOT_AVAILABLE
        task.sync_status = "ERROR"
        task.sync_error = str(exc)[:4000]
        task.last_synced_at = datetime.now(timezone.utc)
        db.commit()
    finally:
        client.close()
    return task


def fail_task(db: Session, task: RpmScanTask, values: dict[str, Any]) -> RpmScanTask:
    if not accepts_event(task.state, "failed"):
        return task
    task.state = FAILED
    task.finished_at = (
        task.finished_at or values.get("finished_at") or datetime.now(timezone.utc)
    )
    task.cbt_exit_code = values.get("cbt_exit_code")
    task.sync_status = "SYNCED"
    task.sync_error = None
    return task
