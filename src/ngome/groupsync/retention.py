"""Which batches may go (decisions 0033 and 0035): a batch is deleted once every member it
is for has pulled past it, and only when it is at least 90 days old."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

MIN_KEEP_MS = 90 * 24 * 60 * 60_000


@dataclass(frozen=True, slots=True)
class BatchRow:
    cursor: int
    id: str
    author: str
    recipient: str | None
    at: int


def expired_batches(
    batches: Iterable[BatchRow],
    acked: Mapping[str, int],
    now_ms: int,
    min_keep_ms: int = MIN_KEEP_MS,
) -> list[BatchRow]:
    """The batches that may be deleted. ``acked`` maps each current member key to the cursor
    it has pulled past."""
    gone = []
    for batch in batches:
        if now_ms - batch.at < min_keep_ms:
            continue
        if batch.recipient is None:
            readers = [key for key in acked if key != batch.author]
        elif batch.recipient in acked:
            readers = [batch.recipient]
        else:
            readers = []  # a removed recipient will never pull it
        if all(acked[key] >= batch.cursor for key in readers):
            gone.append(batch)
    return gone
