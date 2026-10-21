# Owner steps: make CI a gate (G-11)

**Status at 29e4356: not enforced.** `main` reports `protected: false`, no
ruleset exists, and private vulnerability reporting is off. Until an owner
applies the steps below, CI is advisory: a direct push to `main` lands whatever
CI says, and the rulesets in `.github/rulesets/` are files, not settings.
Nothing in this repository can turn them on; they need a repository admin.

## 1. Require the CI gate on `main`

`.github/rulesets/main.json` is a ruleset in the REST API's format:

- no deletion of `main`, no force-push (`non_fast_forward`);
- every change through a pull request (0 approvals required: see step 2), with
  review threads resolved;
- the status check `CI gate` must pass, reported by GitHub Actions
  (`integration_id` 15368, so another app cannot post a check of that name),
  on a branch that is up to date with `main`.

`CI gate` is the last job of `.github/workflows/ci.yml`. It needs every other
job and passes only if all of them succeeded, so the ruleset names one stable
check instead of every job and matrix label.

```sh
gh api -X POST repos/Stan-lee13/graphite/rulesets --input .github/rulesets/main.json
gh api -X POST repos/Stan-lee13/graphite/rulesets --input .github/rulesets/release-tags.json
gh api repos/Stan-lee13/graphite/rulesets            # both listed, enforcement "active"
```

(Or Settings → Rules → Rulesets → New → Import a ruleset, one file at a time.)

Check it took: a direct `git push origin main` must now be rejected, and a pull
request with a red job must show `CI gate` failing and the merge button blocked.

`release-tags.json` makes `v*` tags immutable (no deletion, no move). The
contract gate (`tests/contract_version_gate.rs`) compares against the last
release tag, so a moved tag would move the baseline it checks against.

## 2. Require an independent review (when a second maintainer exists)

`.github/rulesets/main-review.json` adds one approving review, code-owner
review (`.github/CODEOWNERS`), dismissal of stale approvals and approval of the
last push. It is a separate file because GitHub does not let an author approve
their own pull request: with a single maintainer it blocks every merge. Apply
it the day a second person with write access can review:

```sh
gh api -X POST repos/Stan-lee13/graphite/rulesets --input .github/rulesets/main-review.json
```

Until then, the honest statement is: changes are CI-gated but not independently
reviewed.

## 3. Private vulnerability reporting

```sh
gh api -X PUT repos/Stan-lee13/graphite/private-vulnerability-reporting
```

(Or Settings → Code security → Private vulnerability reporting → Enable.) Then
point `.github/ISSUE_TEMPLATE/config.yml`'s security contact link at
`https://github.com/Stan-lee13/graphite/security/advisories/new` and update
SECURITY.md's reporting section to match, in one pull request.

## 4. Optional, recommended

- **Signed commits** (`{"type": "required_signatures"}` in main.json) once every
  contributor, including automation, signs.
- **Merge queue**: the workflow already runs on `merge_group`, so enabling a
  queue in the ruleset needs no workflow change.
- **Dependabot security updates** and **secret scanning push protection**
  (Settings → Code security).
