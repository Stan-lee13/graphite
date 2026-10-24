"""Fail when a cargo-mutants run scores below a floor.

    python3 scripts/mutation_floor.py mutants.out/outcomes.json 0.80

Score = caught / (caught + missed). Timeouts count as caught (the test run
did not pass on the mutant) and unviable mutants (ones that do not compile)
are excluded, as cargo-mutants itself reports them. A run that tested no
mutant at all fails: an empty run is not a pass.

Round 36 (F-015): a run that did not finish its shard fails too. The first
hosted run of these jobs hit the job's six-hour limit on every shard, and a
score over the mutants that happened to run would read as the module's
score. The outcomes must account for every one of `total_mutants`, the
shard's own count; otherwise the partial score is printed and the run is
reported INCOMPLETE.
"""
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
    total = doc.get("total_mutants")
    seen = tested + counts["unviable"]
    if not isinstance(total, int) or seen < total:
        print(
            f"INCOMPLETE: {seen} of {total} mutants in this shard have an outcome; "
            f"partial score {score:.3f} is not the module's (floor {floor:.3f}): {counts}",
            file=sys.stderr,
        )
        return 1
    print(f"mutation score {score:.3f} over all {total} mutants (floor {floor:.3f}): {counts}")
    return 0 if score >= floor else 1


if __name__ == "__main__":
    sys.exit(main())
