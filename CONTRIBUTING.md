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

## Checks run on your machine

GitHub only builds, releases and deploys; the checks run locally. Once per clone:

```sh
tool/setup-hooks
```

Then every `git push` runs the full `tool/check` (lint, format, mypy, unit tests, migrations on Postgres, object storage on MinIO, Docker build) and checks that the titles of the commits you push follow Conventional Commits. Start Postgres and MinIO with `docker compose up -d --wait db minio` so those steps run; without them they are skipped with a notice. `tool/check --fast` (lint, format, types, unit tests) is there for a quick run by hand. In an emergency, `git push --no-verify` skips the hook. See "Testing" in the README.

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
- Commit messages: one short Conventional Commits line, e.g. `feat: add rate limit to code requests`. The pre-push hook rejects other titles (merge commits excepted).
- New dependencies need a reason in the pull request.
