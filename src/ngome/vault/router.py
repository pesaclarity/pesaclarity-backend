"""Backup vault endpoints. Bodies are ``application/octet-stream`` ciphertext, never JSON."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Request, Response, status
from fastapi.responses import StreamingResponse

from ngome.api.deps import BlobStoreDep, PrincipalDep, SessionDep, SettingsDep
from ngome.core.logging import get_logger
from ngome.vault import service
from ngome.vault.models import Backup
from ngome.vault.schemas import BackupOut
from ngome.vault.storage import BlobNotFoundError

log = get_logger(__name__)

# TODO(integrity): accept uploads only from genuine installs once Play Integrity checks land.
router = APIRouter(prefix="/v1/vault/backups", tags=["vault"])

_OCTET_STREAM = "application/octet-stream"


def _out(backup: Backup) -> BackupOut:
    return BackupOut(
        id=backup.id,
        size_bytes=backup.size_bytes,
        sha256=backup.sha256,
        created_at=backup.created_at,
    )


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {_OCTET_STREAM: {"schema": {"type": "string", "format": "binary"}}},
        }
    },
)
async def upload(
    request: Request,
    principal: PrincipalDep,
    session: SessionDep,
    settings: SettingsDep,
    store: BlobStoreDep,
    content_type: Annotated[str | None, Header()] = None,
    x_content_sha256: Annotated[str | None, Header(pattern=r"^[0-9a-fA-F]{64}$")] = None,
) -> BackupOut:
    """Store a backup that the phone has already encrypted.

    Send ``X-Content-SHA256`` (hex) to have the server reject a body corrupted in transit.
    """
    if content_type is None or content_type.split(";")[0].strip() != _OCTET_STREAM:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, f"Send {_OCTET_STREAM}")
    declared = request.headers.get("content-length")
    if (
        declared is not None
        and declared.isdigit()
        and int(declared) > settings.vault_max_backup_bytes
    ):
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "Backup is too large")
    try:
        backup = await service.store_backup(
            session,
            store,
            principal.account_id,
            request.stream(),
            max_bytes=settings.vault_max_backup_bytes,
            expected_sha256=x_content_sha256,
            keep=settings.vault_keep_backups,
            quota_bytes=settings.vault_max_account_bytes,
        )
    except service.BackupTooLargeError:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "Backup is too large") from None
    except service.QuotaExceededError:
        raise HTTPException(
            status.HTTP_413_CONTENT_TOO_LARGE,
            "Backup would take this account over its storage quota",
        ) from None
    except service.BackupTooSmallError:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "That does not look like an encrypted backup"
        ) from None
    except service.ChecksumMismatchError:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "Checksum does not match the upload"
        ) from None
    return _out(backup)


@router.get("")
async def list_backups(principal: PrincipalDep, session: SessionDep) -> list[BackupOut]:
    return [_out(b) for b in await service.list_backups(session, principal.account_id)]


@router.get(
    "/{backup_id}",
    response_class=Response,
    responses={
        200: {"content": {_OCTET_STREAM: {"schema": {"type": "string", "format": "binary"}}}}
    },
)
async def download(
    backup_id: uuid.UUID, principal: PrincipalDep, session: SessionDep, store: BlobStoreDep
) -> Response:
    backup = await service.get_backup(session, principal.account_id, backup_id)
    if backup is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Backup not found")
    try:
        chunks = await store.open(backup.object_key)
    except BlobNotFoundError:
        log.error("vault.blob_missing", backup_id=str(backup.id))
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Backup not found") from None
    return StreamingResponse(
        chunks,
        media_type=_OCTET_STREAM,
        headers={
            "Content-Length": str(backup.size_bytes),
            "X-Content-SHA256": backup.sha256,
            "Cache-Control": "no-store",
        },
    )


@router.delete("/{backup_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete(
    backup_id: uuid.UUID, principal: PrincipalDep, session: SessionDep, store: BlobStoreDep
) -> None:
    if not await service.delete_backup(session, store, principal.account_id, backup_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Backup not found")
