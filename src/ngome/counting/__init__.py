"""Counting active installs without identifiers (ADR 0024).

The app sends a random token, new each month, in the ``Count-Token`` header of the app status
check-in. The server keeps only a keyed digest of it per open day and month, deletes the
digests and keys when the period closes, and keeps totals that name no one.
"""
