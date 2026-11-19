"""The owner's read-only dashboard at ``/admin`` (ADR 0024).

Server-rendered HTML with charts drawn as inline SVG, no third-party scripts, fonts or
requests. It opens only with a passkey on the allow-list (``admin_passkeys``); passkeys are
enrolled through a single-use link minted with the admin token, which never reaches a
browser.
"""
