"""The signed-in account: what we hold, and erasing it."""

import uuid
from datetime import datetime

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from ngome.api.deps import BlobStoreDep, PrincipalDep, SessionDep
from ngome.auth import service
from ngome.auth.models import Account, ContactKind
from ngome.vault import service as vault_service

router = APIRouter(prefix="/v1/account", tags=["account"])


class AccountOut(BaseModel):
    id: uuid.UUID
    contact_kind: ContactKind
    created_at: datetime


@router.get("")
async def get_account(principal: PrincipalDep, session: SessionDep) -> AccountOut:
    account = await session.get(Account, principal.account_id)
    if account is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Account not found")
    return AccountOut(
        id=account.id, contact_kind=account.contact_kind, created_at=account.created_at
    )


@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
async def delete_account(principal: PrincipalDep, session: SessionDep, store: BlobStoreDep) -> None:
    """Erase the account, its devices, sign-in history and every backup straight away.

    The Data Protection Act allows up to 30 days; deleting synchronously keeps us well inside that.
    """
    await service.delete_account(session, principal.account_id)
    # Metadata is gone and the objects are queued; a failed object delete is retried later.
    await vault_service.sweep_deletions(session, store)
