# Heroku web process. Heroku sets PORT and terminates TLS at its router, which
# sits in front of every dyno, so forwarded headers from any address are trusted.
ARG BASE=ngome:base
FROM ${BASE}
CMD uvicorn ngome.api.app:create_app --factory --host 0.0.0.0 --port "${PORT:-8000}" \
    --no-access-log --proxy-headers --forwarded-allow-ips "*"
