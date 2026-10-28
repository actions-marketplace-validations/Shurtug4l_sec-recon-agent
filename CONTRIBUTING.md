# Contributing

Single-author portfolio repo, but the workflow is the one a team would use: PR-only, protected `main`, required checks. This file documents the local setup and the flow any change follows.

## Local setup

```bash
uv sync --extra dev                  # backend deps + dev tooling
uv run pre-commit install            # writes .git/hooks/pre-commit
cd frontend && npm install --legacy-peer-deps && cd ..
```

`pre-commit` runs `ruff --fix`, `ruff format`, a tightly-scoped `mypy --strict src/`, plus the standard `pre-commit-hooks` suite (trailing-whitespace, end-of-file-fixer, YAML / TOML / merge-conflict / oversized-file checks) on every `git commit`. To run it manually across the whole tree:

```bash
uv run pre-commit run --all-files
```

Frontend lint stays in CI only: the npm install footprint is heavier than what a local hook should impose, and the frontend ESLint + TypeScript pipeline is already enforced by the `type-check + build` required check on every PR.

## Branch protection

`main` is a protected branch on GitHub. The protection rules are:

- **Pull-request only**: no direct push to `main`. Every change lands through a PR.
- **Required status checks**: `lint + type-check + tests` (backend) and `type-check + build` (frontend) must be green before a PR can be merged. The audit trail tests, the SBOM contract tests, and the red-team scorer all run inside the backend job.
- **Branches up to date before merging**: enforces rebase against `main` before the merge button is clickable.
- **Linear history**: prevents merge commits. The history reads as a clean sequence of intentional commits, never a tree of fix-ups.
- **No force pushes, no deletions, no bypasses**: applies to admins as well. The rules describe how the project actually works, not how it would work if someone remembers to follow them.

## PR flow

```bash
git checkout -b <type>/<slug>       # feat/, fix/, chore/, docs/, ci/
# ...edits, lint, mypy, pytest locally...
git push -u origin <type>/<slug>
gh pr create --title "<type>(<scope>): <subject>"
gh pr checks <n> --watch            # wait for CI
gh pr merge <n> --rebase --delete-branch
```

Commit subjects follow Conventional Commits; the body explains *why*, not *what* (the diff already says *what*). Public commit history under `git log` on `main` is the canonical record.

## Before touching behavior-bearing text

The system prompt (`src/sec_recon_agent/agent/prompts.py`) and the MCP tool descriptions the LLM consumes are behavior-bearing: a wording change can shift tool-selection or output quality. Any edit there requires re-running `make eval` and `make redteam` before merge, and comparing against the current [SCORECARD.md](SCORECARD.md).

This rule is partly enforced by CI: the replay gate (`tests/replay/`) hashes the LLM-visible surface (system prompt, MCP tool schemas, `TriageReport` schema) and hard-fails when it no longer matches the hash stamped in the committed cassettes. A PR that touches behavior-bearing text must ship re-recorded cassettes (`make record-cassettes`, bills the LLM against a live stack; see [docs/evaluation.md](docs/evaluation.md#record-replay-gate)).

## Cutting a release

The version lives in `pyproject.toml` and nowhere else: `sec_recon_agent.version.package_version()` reads it from the installed metadata for the gate report, the SARIF driver, the OpenTelemetry resource and the API. Two tags (v0.1.1, v0.1.2) went out reporting `tool_version: 0.1.0` because the bump was nobody's step.

1. In a PR: bump `version` in `pyproject.toml`, run `uv lock`, and point the action snippets in `README.md` and `docs/running.md` at the new tag (then `npm run generate:docs` in `frontend/`). Merge on green.
2. Tag the merge commit, signed and annotated: `git tag -s vX.Y.Z -m "sec-recon-agent vX.Y.Z"`, then `git push origin vX.Y.Z`. The tag push runs `release-images` (both images, amd64 + arm64, under four minutes).
3. `gh release create vX.Y.Z --verify-tag` with notes that say what a consumer of the action must do, if anything.
4. In the web UI, edit the release and tick **Publish this Action to the GitHub Marketplace**. There is no API for it.
5. Verify as a consumer, not as the author: `docker buildx imagetools inspect ghcr.io/shurtug4l/sec-recon-agent:X.Y.Z` shows both platforms plus attestations, and the action installs from the tag (`git archive vX.Y.Z | tar -x`, then the three install commands from `action.yml`).

If `release-images` fails on a tag, re-running it cannot help: a tag push always runs the workflow file frozen in the tagged commit. Fix the workflow on `main`, then dispatch it with `release-tag=vX.Y.Z` (and `only=<image>` when the other image already published, so its digest does not move).

## The auto-merge GitHub App

Dependabot PRs that clear the policy in `dependabot-auto-merge.yml` are armed by a GitHub App (`sec-recon-automerge`), not by `GITHUB_TOKEN`, so that the resulting merge triggers the `push` workflows (`docker-scan`, `sbom-gate`, attestations, the Pages redeploy). The App has Contents and Pull requests write, is installed on this repository only, and its token is minted per run, scoped down again, and revoked after the job.

- Configuration: repository variable `AUTOMERGE_APP_CLIENT_ID`, Actions secret `AUTOMERGE_APP_PRIVATE_KEY`. Nothing else, and no copy of the key on disk.
- **Self-test**: `gh workflow run "Dependabot auto-merge"`. It mints the token, asserts it can see exactly this repository, and arms nothing. Run it after any change to the App.
- **Rotating the key**: App settings -> *Private keys* -> *Generate a private key*; `gh secret set AUTOMERGE_APP_PRIVATE_KEY < new.pem`; run the self-test; delete the old key on the same settings page; delete the `.pem`.
- If minting fails, the job falls back to `GITHUB_TOKEN` with a `::warning::` rather than blocking dependency merges. A fallback run merges fine and triggers no push workflows, so treat that warning as a fault to fix, not as noise.
