"""Shared helper behind the "refresh" action of the scan task pages.

Both the RPM and the SRPM page re-read Jenkins for tasks that are already
registered in the portal but have not reached a terminal state yet. The
scan-specific parts are supplied by the caller: the ORM model, the column
that holds the state, the non-terminal states, and how to sync one task.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings
from .jenkins import JenkinsClient
from .scan_state import is_terminal
from .task_writes import lock_task


TaskSync = Callable[[Session, JenkinsClient, Settings, Any], Any]


def resync_registered_tasks(
    settings: Settings,
    db: Session,
    *,
    model: type[Any],
    state_column: Any,
    active_states: Iterable[str],
    sync_one: TaskSync,
) -> dict[str, int]:
    """Re-sync registered tasks whose state is not terminal yet."""
    tasks = db.scalars(
        select(model)
        .where(state_column.in_(tuple(active_states)))
        .order_by(model.id.desc())
        .limit(settings.recent_build_limit)
    ).all()

    client = JenkinsClient(
        settings.jenkins_base_url,
        settings.jenkins_user,
        settings.jenkins_token,
        settings.request_timeout_seconds,
    )
    synced = failed = 0
    try:
        for task in tasks:
            try:
                sync_one(db, client, settings, task)
                db.commit()
                synced += 1
            except Exception as exc:
                db.rollback()
                current = db.get(model, task.id)
                if current is not None:
                    lock_task(db, current)
                    if not is_terminal(getattr(current, state_column.key)):
                        current.sync_status = "ERROR"
                        current.sync_error = str(exc)[:4000]
                        current.last_synced_at = datetime.now(timezone.utc)
                    db.commit()
                failed += 1
    finally:
        client.close()
    return {"synced": synced, "failed": failed}
