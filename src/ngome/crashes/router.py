"""``POST /v1/crash-reports``: needs no account, sets no cookie, logs nothing of the body."""

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import ValidationError

from ngome.api.deps import SessionDep, SettingsDep
from ngome.core.logging import get_logger
from ngome.core.security import utcnow
from ngome.crashes import service
from ngome.crashes.schemas import MAX_REPORT_BYTES, CrashReport

router = APIRouter(prefix="/v1", tags=["crash reports"])
log = get_logger(__name__)


async def _read_capped(request: Request) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > MAX_REPORT_BYTES):
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "Report too large")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_REPORT_BYTES:
            raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "Report too large")
    return bytes(body)


@router.post("/crash-reports", status_code=status.HTTP_202_ACCEPTED)
async def receive_crash_report(
    request: Request, session: SessionDep, settings: SettingsDep
) -> Response:
    """Store one report. The body must be exactly the schema in ``ngome.crashes.schemas``
    (16 KB at most); anything else is refused with 422 and not stored."""
    if not settings.crash_reports_enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    raw = await _read_capped(request)
    try:
        report = CrashReport.model_validate_json(raw)
    except ValidationError:
        # The errors could echo the body back, so none are returned or logged.
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Not a crash report") from None
    try:
        await service.store(session, settings, report, today=utcnow().date())
    except service.DailyCapError:
        log.warning("crash_reports.daily_cap")
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Try again tomorrow") from None
    return Response(status_code=status.HTTP_202_ACCEPTED, headers={"Cache-Control": "no-store"})
