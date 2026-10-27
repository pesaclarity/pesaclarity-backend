# Heroku release phase: runs before each new release goes live.
ARG BASE=ngome:base
FROM ${BASE}
CMD ["alembic", "upgrade", "head"]
