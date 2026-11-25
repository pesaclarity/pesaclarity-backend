// Which batches the daily job may delete (decision 0033): a batch goes once
// every member it is for has pulled past it, and only when it is at least
// 90 days old.

import { MIN_KEEP_MS } from "./protocol.ts";

export type BatchRow = {
  cursor: number;
  id: string;
  author: string;
  recipient: string | null;
  at: number;
};

/** [acked] maps each current member key to the cursor it has pulled past. */
export function expiredBatches(
  batches: readonly BatchRow[],
  acked: ReadonlyMap<string, number>,
  now: number,
  minKeepMs = MIN_KEEP_MS,
): BatchRow[] {
  return batches.filter((b) => {
    if (now - b.at < minKeepMs) return false;
    const readers =
      b.recipient === null
        ? [...acked.keys()].filter((k) => k !== b.author)
        : acked.has(b.recipient)
          ? [b.recipient]
          : []; // a removed recipient will never pull it
    return readers.every((k) => (acked.get(k) ?? 0) >= b.cursor);
  });
}
