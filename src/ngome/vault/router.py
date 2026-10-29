"""Backup vault endpoints. Bodies are ``application/octet-stream`` ciphertext, never JSON."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Request, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from ngome.api.deps import (
    BlobStoreDep,
    IntegrityVerifierDep,
    PrincipalDep,
    SessionDep,
    SettingsDep,
)
from ngome.core.config import Settings
from ngome.core.logging import get_logger
from ngome.integrity import service as integrity_service
from ngome.integrity.apple import AppAttestPolicy
from ngome.integrity.play import (
    IntegrityFailedError,
    IntegrityUnavailableError,
    IntegrityVerifier,
    request_hash_of_sha256_hex,
)
from ngome.vault import service
from ngome.vault.models import Backup
from ngome.vault.schemas import BackupOut
from ngome.vault.storage import BlobNotFoundError

log = get_logger(__name__)

router = APIRouter(prefix="/v1/vault/backups", tags=["vault"])

_OCTET_STREAM = "application/octet-stream"
# Matches the app's header (lib/src/core/integrity/integrity_attestor.dart).
_INTEGRITY_HEADER = "X-Pesaclarity-Integrity"
_MAX_INTEGRITY_TOKEN = 16 * 1024


async def _check_integrity(
    settings: Settings,
    verifier: IntegrityVerifier,
    apple: AppAttestPolicy | None,
    session: AsyncSession,
    account_id: uuid.UUID,
    token: str | None,
    sha256_hex: str | None,
) -> None:
    """Apply the integrity policy to an upload before its body is read.

    Play builds send a Play Integrity token; iPhone builds send an App Attest assertion
    (``appattest <key id> <assertion>``). A proof whose check is switched off counts as none.
    """
    if not verifier.enabled and apple is None:
        return
    assertion = None
    if token is not None:
        try:
            assertion = integrity_service.parse_header(token)
        except IntegrityFailedError:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, "This install could not be verified"
            ) from None
        if not (apple is not None if assertion is not None else verifier.enabled):
            token = None
    if token is None:
        if settings.vault_unattested_uploads == "reject":
            log.info("integrity.unattested_rejected")
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Uploads need a verified install")
        log.info("integrity.unattested_allowed")
        return
    if sha256_hex is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"Send X-Content-SHA256 with {_INTEGRITY_HEADER}",
        )
    request_hash = request_hash_of_sha256_hex(sha256_hex)
    try:
        if assertion is not None and apple is not None:
            key_id, signed = assertion
            await integrity_service.check_assertion(
                session, account_id, key_id, signed, request_hash, apple
            )
        else:
            await verifier.verify(token, request_hash)
    except IntegrityFailedError as exc:
        log.info("integrity.failed", reason=exc.reason)
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "This install could not be verified"
        ) from None
    except IntegrityUnavailableError:
        log.warning("integrity.unavailable")
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Could not verify this install now. Try again later.",
            headers={"Retry-After": "60"},
        ) from None
    log.info("integrity.passed")


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
    integrity: IntegrityVerifierDep,
    content_type: Annotated[str | None, Header()] = None,
    x_content_sha256: Annotated[str | None, Header(pattern=r"^[0-9a-fA-F]{64}$")] = None,
    x_pesaclarity_integrity: Annotated[str | None, Header(max_length=_MAX_INTEGRITY_TOKEN)] = None,
) -> BackupOut:
    """Store a backup that the phone has already encrypted.

    Send ``X-Content-SHA256`` (hex) to have the server reject a body corrupted in transit.
    Play builds also send ``X-Pesaclarity-Integrity``, a Play Integrity token bound to that
    hash, and iPhone builds an App Attest assertion over it; the checksum check then ties the
    proof to the stored bytes.
    """
    if content_type is None or content_type.split(";")[0].strip() != _OCTET_STREAM:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, f"Send {_OCTET_STREAM}")
    await _check_integrity(
        settings,
        integrity,
        request.app.state.app_attest_policy,
        session,
        principal.account_id,
        x_pesaclarity_integrity,
        x_content_sha256,
    )
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
