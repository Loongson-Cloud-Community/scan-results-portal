from __future__ import annotations

from fastapi import HTTPException
from fastapi.responses import Response, StreamingResponse

from ....config import get_settings
from ....jenkins import JenkinsClient
from ....artifact_policy import artifact_response_options
from ..models import RpmScanArtifact, RpmScanTask


def get_artifact(task: RpmScanTask, artifact_id: int) -> RpmScanArtifact:
    artifact = next((row for row in task.artifacts if row.id == artifact_id), None)
    if artifact is None:
        raise HTTPException(status_code=404, detail="RPM scan artifact not found")
    return artifact


def artifact_response(
    task: RpmScanTask,
    artifact: RpmScanArtifact,
    *,
    download: bool,
) -> Response:
    settings = get_settings()
    max_bytes = settings.artifact_limits.max_download_bytes
    if artifact.size_bytes is not None and artifact.size_bytes > max_bytes:
        raise HTTPException(status_code=413, detail="artifact is too large to serve")
    client = JenkinsClient(
        settings.jenkins_base_url,
        settings.jenkins_user,
        settings.jenkins_token,
        settings.request_timeout_seconds,
    )
    job_name = task.jenkins_job_full_name
    build_number = task.jenkins_build_number
    relative_path = artifact.relative_path

    def body():
        try:
            yield from client.iter_artifact(
                job_name,
                build_number,
                relative_path,
                max_bytes=max_bytes,
            )
        finally:
            client.close()

    options = artifact_response_options(
        artifact_type=artifact.artifact_type,
        filename=artifact.name,
        download=download,
    )
    return StreamingResponse(content=body(), **options)
