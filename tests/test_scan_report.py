"""Tests for scripts/scan_report.py using a two-run fixture pair.

scan_report_run1.json / scan_report_run2.json model a scanReport JSON
between two scans of a changing image: click's vulnerable package is
removed entirely between run1 and run2, and a new Jinja2 package with a
new high-severity CVE is introduced. Everything else is unchanged. This
exercises the new/fixed diff logic against a realistic (name, version,
path, CVE) identity key without depending on a live Sysdig account.
"""
import importlib.util
import json
import pathlib
import subprocess
import sys

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
SCRIPT = pathlib.Path(__file__).parent.parent / "scripts" / "scan_report.py"

spec = importlib.util.spec_from_file_location("scan_report", SCRIPT)
scan_report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan_report)


def test_load_findings_applies_severity_filter():
    findings = scan_report.load_findings(FIXTURES / "scan_report_run1.json", "medium")
    cves = {f["cve"] for f in findings}
    assert cves == {"CVE-2026-7246", "CVE-2023-30861", "CVE-2026-27205", "CVE-2022-29361"}
    assert "CVE-2023-23934" not in cves  # low severity, filtered out


def test_load_findings_any_includes_low_severity():
    findings = scan_report.load_findings(FIXTURES / "scan_report_run1.json", "negligible")
    cves = {f["cve"] for f in findings}
    assert "CVE-2023-23934" in cves


def test_diff_detects_new_and_fixed_across_runs():
    run1 = scan_report.load_findings(FIXTURES / "scan_report_run1.json", "medium")
    run2 = scan_report.load_findings(FIXTURES / "scan_report_run2.json", "medium")

    diff = scan_report.diff_findings(run2, run1)

    new_cves = {f["cve"] for f in diff["new"]}
    fixed_cves = {f["cve"] for f in diff["fixed"]}
    assert new_cves == {"CVE-2024-56326"}
    assert fixed_cves == {"CVE-2026-7246"}
    # Unchanged findings (Flask, Werkzeug) must appear in neither list.
    assert "CVE-2023-30861" not in new_cves | fixed_cves
    assert "CVE-2022-29361" not in new_cves | fixed_cves


def test_diff_is_none_without_a_baseline():
    run1 = scan_report.load_findings(FIXTURES / "scan_report_run1.json", "medium")
    assert scan_report.diff_findings(run1, None) is None


def test_finding_key_distinguishes_same_cve_different_package_version():
    a = {"package": "Flask", "version": "1.1.2", "path": "p", "cve": "CVE-X"}
    b = {"package": "Flask", "version": "1.1.4", "path": "p", "cve": "CVE-X"}
    assert scan_report.finding_key(a) != scan_report.finding_key(b)


def run_cli(tmp_path, report_fixture, baseline_path, image="test-image"):
    out_dir = tmp_path / "out"
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            str(FIXTURES / report_fixture),
            "--min-severity",
            "medium",
            "--baseline",
            str(baseline_path),
            "--out-dir",
            str(out_dir),
            "--image",
            image,
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return out_dir


def test_end_to_end_first_run_has_no_diff_and_writes_baseline(tmp_path):
    baseline = tmp_path / "baseline" / "findings.json"
    out_dir = run_cli(tmp_path, "scan_report_run1.json", baseline)

    report = json.loads((out_dir / "vulnerability-report.json").read_text())
    assert report["diff"] is None
    assert report["severity_counts"]["critical"] == 2

    assert baseline.is_file()
    saved = json.loads(baseline.read_text())
    assert len(saved) == 4


def test_end_to_end_second_run_diffs_against_saved_baseline(tmp_path):
    baseline = tmp_path / "baseline" / "findings.json"
    run_cli(tmp_path, "scan_report_run1.json", baseline)
    out_dir = run_cli(tmp_path, "scan_report_run2.json", baseline)

    report = json.loads((out_dir / "vulnerability-report.json").read_text())
    assert report["diff"] is not None
    assert [f["cve"] for f in report["diff"]["new"]] == ["CVE-2024-56326"]
    assert [f["cve"] for f in report["diff"]["fixed"]] == ["CVE-2026-7246"]

    md = (out_dir / "vulnerability-report.md").read_text()
    assert "New since last scan (1)" in md
    assert "Fixed since last scan (1)" in md


def test_missing_report_file_warns_and_exits_zero_without_output(tmp_path):
    out_dir = tmp_path / "out"
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            str(tmp_path / "does-not-exist.json"),
            "--out-dir",
            str(out_dir),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "missing or empty" in result.stderr
    assert not out_dir.exists()
