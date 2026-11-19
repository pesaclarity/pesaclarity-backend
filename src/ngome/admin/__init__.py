"""The owner's dashboard at ``/admin`` (ADR 0024), and its sign-in (ADR 0025).

Server-rendered HTML with charts drawn as inline SVG, no third-party scripts, fonts or
requests. Sign-in is a username and password, then a second factor: the authenticator app
(required), a passkey, an emailed code or a recovery code. The admin user is made from a
terminal with the admin token, which never reaches a browser.
"""
