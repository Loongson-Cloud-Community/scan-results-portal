"""Bounded reconciliation must rotate through old and new registered scans."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from conftest import FakeJenkinsClient
from scanservice import resync
from scanservice.modules.rpm.models import RpmScanTask
from scanservice.modules.srpm.models import SrpmScanTask


BASE = datetime(2026, 10, 1, tzinfo=timezone.utc)


@pytest.fixture(params=["rpm", "srpm"])
def scan_kind(request):
    return (RpmScanTask, "state") if request.param == "rpm" else (SrpmScanTask, "scan_result")


@pytest.fixture
def scheduler(session, settings, monkeypatch, scan_kind):
    model, state_field = scan_kind

    class Clock:
        value = BASE + timedelta(days=1)

        @classmethod
        def now(cls, _timezone):
            return cls.value

    monkeypatch.setattr(resync, "datetime", Clock)
    clients = []

    def client(*_args):
        result = FakeJenkinsClient()
        clients.append(result)
        return result

    monkeypatch.setattr(resync, "JenkinsClient", client)

    def seed(number, *, state="RUNNING", created=BASE, last_sync=None):
        values = {
            "jenkins_job_full_name": f"packages/package-{number}",
            "jenkins_build_number": number,
            "created_at_service": created,
            "last_synced_at": last_sync,
            state_field: state,
            "sync_status": "ERROR" if state == "NOT_AVAILABLE" else "PENDING",
        }
        if model is RpmScanTask:
            values.update(scan_key=f"{number:064x}", rpm_sha256=f"{number:064x}",
                          rpm_name=f"package-{number}.loongarch64.rpm")
        row = model(**values)
        session.add(row)
        session.commit()
        return row

    def run(callback, *, limit=2):
        return resync.resync_registered_tasks(
            replace(settings, recent_build_limit=limit), session,
            model=model, state_column=getattr(model, state_field),
            active_states=("RUNNING", "NOT_AVAILABLE"), sync_one=callback,
        )

    return seed, run, Clock, clients, state_field


def test_equal_priorities_use_oldest_id_first(scheduler):
    seed, run, _, clients, _ = scheduler
    for number in range(1, 6):
        seed(number)
    seen = []
    run(lambda db, client, settings, task: seen.append(task.jenkins_build_number))
    assert seen == [1, 2]
    assert clients[0].closed


def test_repeated_batches_rotate_even_when_adapter_only_reports_pending(scheduler):
    seed, run, clock, _, _ = scheduler
    tasks = [seed(number) for number in range(1, 7)]
    seen = []
    for _ in range(3):
        run(lambda db, client, settings, task: seen.append(task.jenkins_build_number))
        clock.value += timedelta(seconds=1)
    assert seen == [1, 2, 3, 4, 5, 6]
    assert all(task.last_synced_at is not None for task in tasks)


def test_new_untried_scans_do_not_overtake_older_retry(scheduler):
    seed, run, _, _, _ = scheduler
    seed(1, state="NOT_AVAILABLE", last_sync=BASE + timedelta(hours=1))
    seed(2, created=BASE + timedelta(hours=2))
    seen = []
    run(lambda db, client, settings, task: seen.append(task.jenkins_build_number), limit=1)
    assert seen == [1]


def test_continuous_arrivals_do_not_starve_registered_tasks(scheduler):
    seed, run, clock, _, _ = scheduler
    for number in range(1, 5):
        seed(number)
    seen = []
    for batch in range(4):
        seed(100 + batch, created=clock.value)
        run(lambda db, client, settings, task: seen.append(task.jenkins_build_number), limit=1)
        clock.value += timedelta(seconds=1)
    assert seen == [1, 2, 3, 4]


def test_failed_attempts_rotate_instead_of_blocking_the_queue(scheduler):
    seed, run, clock, clients, _ = scheduler
    tasks = [seed(number, state="NOT_AVAILABLE") for number in range(1, 5)]
    seen = []

    def fail(db, client, settings, task):
        seen.append(task.jenkins_build_number)
        raise RuntimeError("Jenkins temporarily unavailable")

    for _ in range(2):
        assert run(fail) == {"synced": 0, "failed": 2}
        clock.value += timedelta(seconds=1)
    assert seen == [1, 2, 3, 4]
    assert all(task.last_synced_at is not None for task in tasks)
    assert all(task.sync_status == "ERROR" for task in tasks)
    assert all(client.closed for client in clients)


def test_existing_attempt_times_control_order_not_build_number(scheduler):
    seed, run, _, _, _ = scheduler
    seed(1, last_sync=BASE + timedelta(hours=3))
    seed(2, last_sync=BASE + timedelta(hours=1))
    seed(3, last_sync=BASE + timedelta(hours=2))
    seen = []
    run(lambda db, client, settings, task: seen.append(task.jenkins_build_number))
    assert seen == [2, 3]


def test_final_tasks_stay_out_of_reconciliation(scheduler):
    seed, run, _, _, state_field = scheduler
    seed(1, state="FINISHED")
    seed(2, state="FAILED")
    seed(3, state="RUNNING")
    seed(4, state="NOT_AVAILABLE")
    seen = []

    def finish(db, client, settings, task):
        seen.append(task.jenkins_build_number)
        setattr(task, state_field, "FINISHED")
        task.sync_status = "SYNCED"

    run(finish)
    run(finish)
    assert seen == [3, 4]


def test_attempt_time_is_durable_across_session_expiration(scheduler, session):
    seed, run, clock, _, _ = scheduler
    first, second = seed(1), seed(2)
    run(lambda *_args: None, limit=1)
    first_id, second_id = first.id, second.id
    session.expire_all()
    assert session.get(type(first), first_id).last_synced_at.replace(tzinfo=timezone.utc) == clock.value
    assert session.get(type(second), second_id).last_synced_at is None
