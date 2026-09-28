"""Tests for scripts/validate_sarif.py using representative SARIF fixtures.

These fixtures model the shape Sysdig's SARIF presenter produces with
group-by-package=true (rule id = package identity, not bare CVE), plus a
deliberate regression fixture modeling the group-by-package=false bug
(sysdiglabs/scan-action#113). They do not replace scanning a real image -
see docs/runbook.md for the live-account verification pass.
"""
import json
import pathlib
import subprocess
import sys

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
SCRIPT = pathlib.Path(__file__).parent.parent / "scripts" / "validate_sarif.py"


def run_validator(path: pathlib.Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(path)],
        capture_output=True,
        text=True,
    )


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_valid_group_by_package_sarif_passes():
    result = run_validator(FIXTURES / "valid_group_by_package_run1.json")
    assert result.returncode == 0, result.stderr
    assert "2 result(s)" in result.stdout


def test_same_cve_in_two_packages_gets_distinct_rule_ids():
    sarif = load("valid_group_by_package_run1.json")
    rule_ids = [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids)), "rule ids must be unique per package"
    # Both rules represent the same CVE in different packages, but must not
    # collide - that is the whole point of group-by-package=true.
    assert rule_ids[0] != rule_ids[1]
    for rid in rule_ids:
        assert "http2-server" in rid or "http2-common" in rid


def test_rescan_of_unchanged_image_keeps_same_rule_ids_and_fingerprints():
    run1 = load("valid_group_by_package_run1.json")
    run2 = load("valid_group_by_package_run2_rescan.json")

    def identity_set(sarif: dict) -> set:
        return {
            (r["ruleId"], r.get("partialFingerprints", {}).get("sysdigPackageFingerprint"))
            for r in sarif["runs"][0]["results"]
        }

    assert identity_set(run1) == identity_set(run2), (
        "a rescan of the same unchanged image must resolve to the same "
        "(ruleId, fingerprint) pairs, otherwise GitHub opens duplicate alerts "
        "for each rescan instead of tracking one continuing alert"
    )
    # Sanity: the fixtures do differ in some run-level metadata (scanner
    # version), otherwise this test would be meaningless.
    assert (
        run1["runs"][0]["tool"]["driver"]["version"]
        != run2["runs"][0]["tool"]["driver"]["version"]
    )


def test_duplicate_rule_id_regression_is_rejected():
    result = run_validator(FIXTURES / "duplicate_rule_id_regression.json")
    assert result.returncode == 2
    assert "duplicate rule id" in result.stderr


def test_missing_sarif_file_is_a_pipeline_error_not_zero_findings():
    result = run_validator(FIXTURES / "does_not_exist.json")
    assert result.returncode == 2
    assert "missing or empty" in result.stderr


def test_empty_sarif_file_is_a_pipeline_error():
    empty = FIXTURES / "_empty.sarif"
    empty.write_text("", encoding="utf-8")
    try:
        result = run_validator(empty)
        assert result.returncode == 2
        assert "missing or empty" in result.stderr
    finally:
        empty.unlink()


def test_malformed_json_is_a_pipeline_error():
    broken = FIXTURES / "_broken.sarif"
    broken.write_text("{not json", encoding="utf-8")
    try:
        result = run_validator(broken)
        assert result.returncode == 2
        assert "not valid JSON" in result.stderr
    finally:
        broken.unlink()


def test_zero_results_is_a_clean_scan_not_an_error():
    result = run_validator(FIXTURES / "empty_results_clean_scan.json")
    assert result.returncode == 0, result.stderr
    assert "0 result(s)" in result.stdout


def test_absolute_filesystem_path_uri_is_rejected():
    result = run_validator(FIXTURES / "absolute_path_uri.json")
    assert result.returncode == 2
    assert "artifactLocation.uri" in result.stderr


def test_missing_security_severity_and_fingerprints_warn_but_do_not_fail():
    result = run_validator(FIXTURES / "missing_metadata_warnings.json")
    assert result.returncode == 0, result.stderr
    assert "security-severity" in result.stderr
    assert "partialFingerprints" in result.stderr
    assert "level=note" in result.stderr
