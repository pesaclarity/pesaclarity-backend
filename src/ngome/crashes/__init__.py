"""Crash reports the person chose to send (ADR 0024).

A report is an allow-listed set of fields: versions, the system version, the chip, the kind
of error from a fixed list and the stack as code offsets. The app builds it field by field
and shows it before sending; the server checks the same schema again and refuses anything
else. It needs no account, sets no cookie and is not linked to the counting token.
"""
