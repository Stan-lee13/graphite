"""Fail when a cargo-mutants run scores below a floor.

    python3 scripts/mutation_floor.py mutants.out/outcomes.json 0.80

Score = caught / (caught + missed). Timeouts count as caught (the test run
did not pass on the mutant) and unviable mutants (ones that do not compile)
are excluded, as cargo-mutants itself reports them. A run that tested no
mutant at all fails: an empty run is not a pass.

Round 36 (F-015): a run that did not finish its shard fails too. The first
hosted run of these jobs hit the job's six-hour limit on every shard, and a
score over the mutants that happened to run would read as the module's
score. The outcomes must account for every mutant the shard was given;
otherwise the partial score is printed and the run is reported INCOMPLETE.

The shard's count is read from `mutants.json`, written beside
`outcomes.json` before the first mutant runs. `outcomes.json`'s own
`total_mutants` is NOT that count: cargo-mutants 27.1.0 raises it as each
outcome lands, so on a shard killed by the step timeout it equals the
outcomes recorded, and 15 of the 17 killed shards of run 40083338181 were
scored as if complete. An interrupted run also leaves `end_time` null.
"""
import os
import json
import sys


def main() -> int:
    path, floor = sys.argv[1], float(sys.argv[2])
    with open(path) as f:
        doc = json.load(f)
    counts = {"caught": 0, "missed": 0, "timeout": 0, "unviable": 0}
    for outcome in doc.get("outcomes", []):
        scenario = outcome.get("scenario")
        if scenario == "Baseline" or not isinstance(scenario, dict):
            continue
        summary = outcome.get("summary", "")
        key = {
            "CaughtMutant": "caught",
            "MissedMutant": "missed",
            "Timeout": "timeout",
            "Unviable": "unviable",
        }.get(summary)
        if key is None:
            print(f"unrecognised outcome {summary!r}", file=sys.stderr)
            return 2
        counts[key] += 1
    tested = counts["caught"] + counts["missed"] + counts["timeout"]
    if tested == 0:
        print(f"no mutant was tested: {counts}", file=sys.stderr)
        return 1
    score = (counts["caught"] + counts["timeout"]) / tested
    listed = os.path.join(os.path.dirname(path) or ".", "mutants.json")
    try:
        with open(listed) as f:
            total = len(json.load(f))
    except (OSError, ValueError, TypeError) as e:
        print(f"INCOMPLETE: cannot read the shard's mutant list {listed}: {e}", file=sys.stderr)
        return 1
    seen = tested + counts["unviable"]
    if seen != total or doc.get("end_time") is None:
        print(
            f"INCOMPLETE: {seen} of {total} mutants in this shard have an outcome"
            f"{'' if doc.get('end_time') else ' and the run never finished (no end_time)'}; "
            f"partial score {score:.3f} is not the module's (floor {floor:.3f}): {counts}",
            file=sys.stderr,
        )
        return 1
    print(f"mutation score {score:.3f} over all {total} mutants (floor {floor:.3f}): {counts}")
    return 0 if score >= floor else 1


if __name__ == "__main__":
    sys.exit(main())
