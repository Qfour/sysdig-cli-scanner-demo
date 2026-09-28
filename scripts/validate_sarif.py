#!/usr/bin/env python3
"""Validate a SARIF file before it is uploaded to GitHub Code Scanning.

This is a hard gate, not a report: any structural problem here must fail the
pipeline (exit 2) rather than be silently swallowed. A SARIF file with zero
results is a legitimate clean scan and exits 0 - that case must stay
distinguishable from "the file is missing or broken", which is a pipeline
error, not "no findings".
"""
import json
import pathlib
import sys
import urllib.parse

import jsonschema

SCHEMA_PATH = pathlib.Path(__file__).parent / "schemas" / "sarif-2.1.0-schema.json"


def fail(msg: str) -> None:
    print(f"::error::{msg}", file=sys.stderr)
    sys.exit(2)


def load_sarif(path_arg: str) -> dict:
    if not path_arg:
        fail("No SARIF path provided (scanner output was empty).")
    path = pathlib.Path(path_arg)
    if not path.is_file() or path.stat().st_size == 0:
        fail(f"SARIF file '{path}' is missing or empty.")
    try:
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        fail(f"SARIF file '{path}' is not valid JSON: {e}")


def validate_schema(sarif: dict) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    validator = validator_cls(schema)
    errors = sorted(validator.iter_errors(sarif), key=lambda e: list(e.path))
    if errors:
        for e in errors[:20]:
            loc = "/".join(str(p) for p in e.path)
            print(f"::error::SARIF schema violation at '{loc}': {e.message}", file=sys.stderr)
        fail(f"SARIF 2.1.0 schema validation failed with {len(errors)} error(s).")


def validate_unique_rule_ids(sarif: dict) -> None:
    for run_idx, run in enumerate(sarif.get("runs", [])):
        rules = run.get("tool", {}).get("driver", {}).get("rules", []) or []
        seen: dict = {}
        for rule in rules:
            rule_id = rule.get("id")
            if not rule_id:
                fail(f"run[{run_idx}]: a rule in tool.driver.rules has no 'id'.")
            seen[rule_id] = seen.get(rule_id, 0) + 1
        dupes = {rid: n for rid, n in seen.items() if n > 1}
        if dupes:
            sample = ", ".join(f"{rid} x{n}" for rid, n in list(dupes.items())[:10])
            fail(
                f"run[{run_idx}]: duplicate rule id(s) in tool.driver.rules: {sample}. "
                "GitHub does not reject this - it silently dedupes and shows an arbitrary "
                "package in the alert description/help text instead (see "
                "sysdiglabs/scan-action#113, per-vulnerability mode with "
                "group-by-package=false). Fix the scan/report generation before uploading."
            )


def validate_result_uris(sarif: dict) -> None:
    for run_idx, run in enumerate(sarif.get("runs", [])):
        for result_idx, result in enumerate(run.get("results", []) or []):
            locations = result.get("locations") or []
            if not locations:
                fail(f"run[{run_idx}].results[{result_idx}]: no locations present.")
            for loc in locations:
                uri = (loc.get("physicalLocation") or {}).get("artifactLocation", {}).get("uri")
                if not uri:
                    fail(f"run[{run_idx}].results[{result_idx}]: missing artifactLocation.uri.")
                parsed = urllib.parse.urlparse(uri)
                if parsed.scheme == "" and uri.startswith("/"):
                    fail(
                        f"run[{run_idx}].results[{result_idx}]: artifactLocation.uri "
                        f"'{uri}' looks like an absolute filesystem path from the build "
                        "host rather than a repo-relative URI - GitHub cannot anchor the "
                        "alert to a file with this."
                    )


def warn_fingerprint_and_severity_gaps(sarif: dict) -> None:
    for run_idx, run in enumerate(sarif.get("runs", [])):
        rules = run.get("tool", {}).get("driver", {}).get("rules", []) or []
        for rule in rules:
            props = rule.get("properties") or {}
            if "security-severity" not in props:
                print(
                    f"::warning::run[{run_idx}] rule '{rule.get('id')}' has no "
                    "properties['security-severity']; GitHub Code Scanning derives the "
                    "displayed severity badge from this field, not from result.level.",
                    file=sys.stderr,
                )

        results = run.get("results", []) or []
        levels = {r.get("level", "warning") for r in results}
        if results and levels == {"note"}:
            print(
                "::warning::every result in this run has level=note. Sysdig's SARIF "
                "presenter has a known bug where the severity->level lookup always "
                "matches 'note' regardless of actual severity (same class of mistake as "
                "scan-action#113: array membership tested with 'in'). This does not move "
                "the GitHub severity badge (driven by security-severity), but does affect "
                "PR annotation levels for third-party SARIF consumers.",
                file=sys.stderr,
            )

        without_fingerprint = sum(1 for r in results if not r.get("partialFingerprints"))
        if results and without_fingerprint:
            print(
                f"::warning::{without_fingerprint}/{len(results)} result(s) in run[{run_idx}] "
                "have no partialFingerprints. Without them GitHub falls back to its own "
                "rule+location fingerprint for alert matching across runs - confirm with "
                "the runbook (docs/runbook.md) that a rescan of an unchanged image still "
                "maps to the same alert rather than opening a duplicate.",
                file=sys.stderr,
            )


def main() -> None:
    if len(sys.argv) != 2:
        fail("Usage: validate_sarif.py <path-to-sarif-file>")
    sarif = load_sarif(sys.argv[1])
    validate_schema(sarif)
    validate_unique_rule_ids(sarif)
    validate_result_uris(sarif)
    warn_fingerprint_and_severity_gaps(sarif)

    runs = sarif.get("runs", [])
    total_results = sum(len(run.get("results", []) or []) for run in runs)
    print(f"SARIF valid: {total_results} result(s) across {len(runs)} run(s).")
    # total_results == 0 is a legitimate clean scan, not an error - exit 0 either way.


if __name__ == "__main__":
    main()
