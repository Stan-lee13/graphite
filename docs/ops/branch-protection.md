# Owner steps: make CI a gate and the release tags immutable (G-11, R37-8)

**Live state, read on 2026-10-25 (Round 39) — NOT what the committed files say.**
`GET repos/Stan-lee13/graphite/rulesets` (read with the owner's token) lists one ruleset:

| | live `Main-review` (id 25817024) | committed |
|---|---|---|
| name | `Main-review` | `main — integrity (Round 30, G-11)` (`main.json`) and `main — independent review (…)` (`main-review.json`) |
| rules | deletion, non_fast_forward, pull_request, required_status_checks `CI gate` (app 15368), **copilot_code_review** | `main.json`: the same four, no Copilot rule; `main-review.json`: pull_request only |
| required approvals | **0** | 0 in `main.json`, **1** (code owner, last push) in `main-review.json` |
| `require_extra_approval_for_unattributed_changes` | **true** | not set (off) |
| bypass actors | **RepositoryRole 2 (maintain) and 5 (admin), and 24 GitHub Apps, all `always`** | `main.json`: none; `main-review.json`: admin, `pull_request` only |
| tag rulesets | **none** | `release-tags.json` (immutable `v*`), `release-tags-create.json` (only an admin creates `v*`) |

Private vulnerability reporting: `GET …/private-vulnerability-reporting` = `{"enabled": false}`.
The `release` environment could not be read through the audit session (its API path was not
reachable); treat it as absent until `ruleset-drift.py` reads it.

What the live state means: an admin, a maintainer, and each of the 24 apps that holds write access
can push straight to `main`, force-push it or delete it, without a pull request and without
`CI gate`; nobody's change
is reviewed; any writer can create, move or delete a `v*` tag. The release gate still refuses an
unsigned tag (`.github/allowed_signers` is empty), but a tag on a commit older than the gate runs a
`release.yml` with no gate (R37-8), and only the tag rulesets and the `release` environment stop
that. Nothing in this repository can change these settings; they need a repository admin.

## The live state must be exactly this

`.github/scripts/ruleset-drift.py` (weekly in `ruleset-drift.yml`) compares the live rulesets with
the committed files and passes only when:

- **four rulesets are live, under exactly their committed names**: `main.json`,
  `main-review.json`, `release-tags.json`, `release-tags-create.json`, each `active`, with the
  committed target, refs, rules, parameters and bypass list;
- **no other ruleset exists** (Round 39: one without a committed file is a difference, compared
  field by field with the committed ruleset for the same refs);
- **bypass lists**: `[]` for `main.json` and `release-tags.json`; the admin role (`actor_id` 5)
  with `bypass_mode: pull_request` for `main-review.json`; the admin role with `always` for
  `release-tags-create.json`. **No `Integration` (GitHub App), no maintain role, nothing else**;
- the `release` environment has at least one required reviewer and exactly one deployment policy,
  the tag pattern `v*`.

A rule or parameter you want beyond these (Copilot review, approval of unattributed changes, signed
commits, a merge queue) goes into the committed file first, in a pull request; the check then
expects it.

## 1. Apply the four committed rulesets, then delete `Main-review`

In this order, so `main` is never unprotected. From a checkout of `main`, `gh` logged in as the
repository admin:

```sh
for f in main main-review release-tags release-tags-create; do
  gh api -X POST repos/Stan-lee13/graphite/rulesets --input ".github/rulesets/$f.json"
done
gh api repos/Stan-lee13/graphite/rulesets --jq '.[] | [.id, .name, .enforcement] | @tsv'
#   five lines: the four committed names, all "active", and 25817024 Main-review
gh api -X DELETE repos/Stan-lee13/graphite/rulesets/25817024     # the uncommitted Main-review
```

Or in the browser: Settings → Rules → Rulesets → **New ruleset ▾ → Import a ruleset**, pick
`.github/rulesets/main.json`, keep the name exactly as imported, **Create**; repeat for
`main-review.json`, `release-tags.json` and `release-tags-create.json`. Then open `Main-review` →
**Delete ruleset**. Do not instead edit `Main-review` into shape unless you also rename it to the
committed name, remove both role entries and all 24 apps from its bypass list, remove the
"Copilot code review" rule and clear "Require approval of unattributed changes"; deleting it is
the same result with less to get wrong.

What each piece is:

- `main.json`: no deletion of `main`, no force-push; every change through a pull request (0
  approvals here; review is `main-review.json`), review threads resolved; the status check
  `CI gate` must pass, reported by GitHub Actions (`integration_id` 15368, so another app cannot
  post a check of that name), on a branch up to date with `main`. `CI gate` is the last job of
  `.github/workflows/ci.yml`; it needs every other job. No bypass for anyone.
- `main-review.json`: one approving review, code-owner review (`.github/CODEOWNERS`), stale
  approvals dismissed, the last push approved. GitHub does not let an author approve their own
  pull request, so the admin role may bypass it **through a pull request only** (`bypass_mode:
  pull_request`; never a direct push, and `main.json`'s `CI gate` still applies). With one
  maintainer every merge is then a logged bypass, which is the honest record: changes are
  CI-gated, not independently reviewed. Delete that bypass entry (in the file, by pull request,
  then live) once two maintainers review each other. Since Round 39 this ruleset is required.
- `release-tags.json`: `v*` tags cannot be deleted, moved or force-updated, by anyone. The contract
  gate (`tests/contract_version_gate.rs`) compares against the last release tag, so a moved tag
  would move its baseline.
- `release-tags-create.json`: only an admin creates a `v*` tag. A separate ruleset so that its
  admin bypass does not also let an admin delete or move a tag.

Removing the 24 apps from the bypass list does not uninstall them: their pull requests still run
CI and merge through the rules like anyone's.

## 2. The `release` environment

`docs/ops/production-checklist.md`, R2 (a required reviewer, one deployment policy: tag `v*`).

## 3. Read it back, with the bypass lists

The weekly `Ruleset drift` workflow uses GITHUB_TOKEN, which GitHub does not show bypass lists to;
it passes with them marked **NOT VERIFIED**. Read them once yourself, as admin, with the same
script:

```sh
live="$(mktemp -d)"
gh api 'repos/Stan-lee13/graphite/rulesets?includes_parents=false&per_page=100' > "$live/rulesets.json"
for id in $(jq -r '.[].id' "$live/rulesets.json"); do
  gh api "repos/Stan-lee13/graphite/rulesets/$id" > "$live/ruleset-$id.json"
done
gh api repos/Stan-lee13/graphite/environments/release > "$live/environment-release.json" \
  || rm -f "$live/environment-release.json"
gh api 'repos/Stan-lee13/graphite/environments/release/deployment-branch-policies?per_page=100' \
  > "$live/environment-release-policies.json" || rm -f "$live/environment-release-policies.json"
python3 -I .github/scripts/ruleset-drift.py --live "$live" --require-bypass
```

Done when it exits 0 and prints "the live rulesets, their bypass lists and the release environment
match the committed files". Then: a direct `git push origin main` is rejected; a pull request with a
red job shows `CI gate` failing and the merge blocked; a collaborator without admin cannot push a
`v*` tag; nobody can delete one.

## 4. Private vulnerability reporting

Off on 2026-10-25 (`{"enabled": false}`).

```sh
gh api -X PUT repos/Stan-lee13/graphite/private-vulnerability-reporting
gh api repos/Stan-lee13/graphite/private-vulnerability-reporting      # {"enabled": true}
```

(Or Settings → Code security → Private vulnerability reporting → Enable.) Then, in one pull
request, point `.github/ISSUE_TEMPLATE/config.yml`'s security contact link (today:
`…/blob/main/SECURITY.md`) at `https://github.com/Stan-lee13/graphite/security/advisories/new`, and
make `SECURITY.md`'s "Reporting a Vulnerability" section (today: an e-mail address only) name the
private advisory form first and the address as the fallback.

## 5. Optional, recommended

Each needs its rule in the committed file first, or the drift check reports it.

- **Signed commits** (`{"type": "required_signatures"}` in `main.json`) once every
  contributor, including automation, signs.
- **Merge queue**: the workflow already runs on `merge_group`, so enabling a queue needs no
  workflow change.
- **Dependabot security updates** and **secret scanning push protection**
  (Settings → Code security).
