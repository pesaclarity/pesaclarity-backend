"""Group sync tables. None of them holds an account id, an email, an address or anything
else that links a space or a member key to an account, and none has a foreign key to the
account tables. Times and cursors are whole numbers, as they travel on the wire
(milliseconds since 1970).

The batches themselves, as the phones sent them, are in the blob store
(``ngome.vault.storage``), under a random object key that names neither the space nor the
member.
"""

from sqlalchemy import BigInteger, ForeignKey, Integer, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ngome.db.base import Base
from ngome.groupsync.protocol import ID_LENGTH, KEY_LENGTH
from ngome.vault.models import OBJECT_KEY_LENGTH

# base64url of a SHA-256.
HASH_LENGTH = 43
NONCE_DIGEST_BYTES = 32


class SyncSpace(Base):
    """One shared space: its owner's key, how long the owner's licence lasts, and the last
    cursor given to a batch. Only "valid until" is kept from the licence."""

    __tablename__ = "sync_spaces"

    # The space's random id, made on the owner's phone.
    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    owner_key: Mapped[str] = mapped_column(String(KEY_LENGTH))
    valid_until: Mapped[int] = mapped_column(BigInteger)
    # Raised by one, under a row lock, for each new batch: cursors are never reused, and a
    # lower cursor is always committed before a higher one.
    last_cursor: Mapped[int] = mapped_column(BigInteger, default=0)


class SyncMember(Base):
    """A member's signing key, and the cursor they have pulled past."""

    __tablename__ = "sync_members"

    space_id: Mapped[str] = mapped_column(
        ForeignKey("sync_spaces.id", ondelete="CASCADE"), primary_key=True
    )
    key: Mapped[str] = mapped_column(String(KEY_LENGTH), primary_key=True)
    added_at: Mapped[int] = mapped_column(BigInteger)
    # The cursor they say they hold everything up to (the highest ``since`` they pulled
    # from). Retention counts on it.
    acked: Mapped[int] = mapped_column(BigInteger, default=0)
    # The furthest cursor a pull may have answered them with. A ``since`` beyond it is not
    # from this space as it is now (the space was deleted and made again), and starts over.
    served: Mapped[int] = mapped_column(BigInteger, default=0)


class SyncBatch(Base):
    """The index entry for one batch. Its bytes are in the blob store under ``object_key``."""

    __tablename__ = "sync_batches"
    __table_args__ = (UniqueConstraint("space_id", "batch_id", name="uq_sync_batches_batch"),)

    space_id: Mapped[str] = mapped_column(
        ForeignKey("sync_spaces.id", ondelete="CASCADE"), primary_key=True
    )
    cursor: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    # The sender's id for the batch: sending it again changes nothing.
    batch_id: Mapped[str] = mapped_column(String(ID_LENGTH))
    author: Mapped[str] = mapped_column(String(KEY_LENGTH))
    # The one member it is for, or none when it is for everyone.
    recipient: Mapped[str | None] = mapped_column(String(KEY_LENGTH), nullable=True)
    size: Mapped[int] = mapped_column(Integer)
    hash: Mapped[str] = mapped_column(String(HASH_LENGTH))
    at: Mapped[int] = mapped_column(BigInteger, index=True)
    object_key: Mapped[str] = mapped_column(String(OBJECT_KEY_LENGTH), unique=True)


class SyncNonce(Base):
    """A nonce an accepted request used, kept until a minute after that request could no
    longer pass the clock check, so the same signed request is refused a second time.

    Only a digest is kept: SHA-256 over the space id and the nonce. So a nonce can outlive
    its space, which is what refuses a copy of an old request once a space is deleted and
    made again, and still no row names a deleted space.
    """

    __tablename__ = "sync_nonces"

    digest: Mapped[bytes] = mapped_column(LargeBinary(NONCE_DIGEST_BYTES), primary_key=True)
    expires_at: Mapped[int] = mapped_column(BigInteger, index=True)


class SyncPendingBlob(Base):
    """An object a push is writing, noted before the write and cleared in the transaction
    that records the batch. One left behind by a push that died in between names an object
    nothing points at; the purge deletes it."""

    __tablename__ = "sync_pending_blobs"

    object_key: Mapped[str] = mapped_column(String(OBJECT_KEY_LENGTH), primary_key=True)
    created_at: Mapped[int] = mapped_column(BigInteger, index=True)
