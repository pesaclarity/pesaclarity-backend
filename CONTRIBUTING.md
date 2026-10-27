# Contributing to pesaclarity-backend

Thank you for helping. The code of conduct, security policy and general contribution terms are the organisation defaults in [pesaclarity/.github](https://github.com/pesaclarity/.github). Please report security issues privately as described there, not in public issues.

## Setup

Install [uv](https://docs.astral.sh/uv/) and Docker, then:

```sh
uv sync --all-extras
cp .env.example .env
docker compose up -d db
uv run alembic upgrade head
```

## Before you open a pull request

```sh
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
```

All four must pass; CI runs the same checks, plus the object storage tests on MinIO, the migrations on Postgres and a Docker build. To run the object storage tests locally, see "Testing" in the README.

## Rules for this server

- The server never receives financial data. If a change would let a transaction, balance, message or readable backup reach it, it will not be merged.
- Never log contacts, codes, tokens or request bodies. Log ids, counts and outcomes only.
- Contacts are stored as keyed hashes, never in readable form.
- Schema changes need an Alembic migration: `uv run alembic revision --autogenerate -m "short description"`, then review the generated file.
- Synthetic test data only: obviously fake numbers such as 0700 000 000 and made-up names.
- Add or update tests with every change.

## Commits and pull requests

- Small, focused pull requests against `dev`, with a short description of what changed and why. `main` takes only `dev` and release pull requests (see [Branches and releases](README.md#branches-and-releases)).
- Pull request titles follow [Conventional Commits](https://www.conventionalcommits.org): `feat: add rate limit to code requests`, `fix: …`, `feat!: …` for a breaking change. They set the next version and the changelog.
- Commit messages: one short line in the imperative, e.g. "Add rate limit to code requests".
- New dependencies need a reason in the pull request.
