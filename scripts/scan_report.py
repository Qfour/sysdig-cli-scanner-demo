#!/usr/bin/env python3
"""Build a human-readable vulnerability report from a sysdig-cli-scanner
scanReport JSON, diff it against the previous run's baseline, append a
summary to $GITHUB_STEP_SUMMARY, and write the new baseline for next time.

Identity for diffing matches the SARIF group-by-package rule id scheme
(package name + version + path) rather than bare CVE, so the same CVE
present at two different paths is tracked as two separate findings - the
same reasoning documented in README.md for why group-by-package=true was
chosen for the SARIF upload.
"""
import argparse
import json
import os
import pathlib
import sys

SEVERITY_ORDER = ["negligible", "low", "medium", "high", "critical"]
SEVERITY_EMOJI = {
    "critical": "\U0001f7e3",
    "high": "\U0001f534",
    "medium": "\U0001f7e1",
    "low": "\U0001f7e2",
    "negligible": "⚪",
}


def severity_rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index(sev.lower())
    except ValueError:
        return -1


def load_findings(report_path: pathlib.Path, min_severity: str) -> list:
    data = json.loads(report_path.read_text(encoding="utf-8"))
    result = data.get("result", {})
    packages = result.get("packages", {}) or {}
    vulnerabilities = result.get("vulnerabilities", {}) or {}
    min_rank = severity_rank(min_severity)

    findings = []
    for pkg in packages.values():
        for vuln_ref in pkg.get("vulnerabilitiesRefs") or []:
            vuln = vulnerabilities.get(vuln_ref)
            if vuln is None:
                continue
            severity = (vuln.get("severity") or "unknown").lower()
            if severity_rank(severity) < min_rank:
                continue
            findings.append(
                {
                    "package": pkg.get("name"),
                    "version": pkg.get("version"),
                    "path": pkg.get("path"),
                    "package_type": pkg.get("type"),
                    "cve": vuln.get("name"),
                    "severity": severity,
                    "cvss_score": (vuln.get("cvssScore") or {}).get("score"),
                    "fix_version": vuln.get("fixVersion"),
                    "exploitable": bool(vuln.get("exploitable")),
                }
            )
    findings.sort(key=lambda f: (-severity_rank(f["severity"]), f["package"] or "", f["cve"] or ""))
    return findings


def finding_key(f: dict) -> tuple:
    return (f["package"], f["version"], f["path"], f["cve"])


def diff_findings(current: list, baseline):
    if baseline is None:
        return None
    current_by_key = {finding_key(f): f for f in current}
    baseline_by_key = {finding_key(f): f for f in baseline}
    new = [f for k, f in current_by_key.items() if k not in baseline_by_key]
    fixed = [f for k, f in baseline_by_key.items() if k not in current_by_key]
    new.sort(key=lambda f: -severity_rank(f["severity"]))
    fixed.sort(key=lambda f: -severity_rank(f["severity"]))
    return {"new": new, "fixed": fixed}


def render_table(findings: list) -> str:
    if not findings:
        return "_(none)_\n"
    lines = [
        "| Severity | Package | Version | CVE | CVSS | Fix | Exploitable |",
        "|---|---|---|---|---|---|---|",
    ]
    for f in findings:
        emoji = SEVERITY_EMOJI.get(f["severity"], "")
        cve = f["cve"] or ""
        cve_cell = f"[{cve}](https://nvd.nist.gov/vuln/detail/{cve})" if cve else ""
        lines.append(
            "| {emoji} {sev} | {pkg} | {ver} | {cve} | {cvss} | {fix} | {expl} |".format(
                emoji=emoji,
                sev=f["severity"],
                pkg=f["package"],
                ver=f["version"],
                cve=cve_cell,
                cvss=f.get("cvss_score", ""),
                fix=f.get("fix_version") or "N/A",
                expl="⚠️ yes" if f.get("exploitable") else "no",
            )
        )
    return "\n".join(lines) + "\n"


def severity_counts(findings: list) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        if f["severity"] in counts:
            counts[f["severity"]] += 1
    return counts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=pathlib.Path)
    parser.add_argument("--min-severity", default="medium")
    parser.add_argument("--baseline", type=pathlib.Path)
    parser.add_argument("--out-dir", type=pathlib.Path, required=True)
    parser.add_argument("--image", default="")
    args = parser.parse_args()

    if not args.report.is_file() or args.report.stat().st_size == 0:
        print(
            "::warning::scanReport is missing or empty; skipping vulnerability report "
            "generation (SARIF validation already treats a missing scanner output as a "
            "pipeline error, this step just has nothing to summarize).",
            file=sys.stderr,
        )
        return

    current = load_findings(args.report, args.min_severity)

    baseline = None
    if args.baseline and args.baseline.is_file():
        try:
            baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print(
                "::warning::baseline findings file is corrupt; treating as first run.",
                file=sys.stderr,
            )
            baseline = None

    diff = diff_findings(current, baseline)
    counts = severity_counts(current)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    report_json = {
        "image": args.image,
        "min_severity": args.min_severity,
        "severity_counts": counts,
        "findings": current,
        "diff": diff,
    }
    (args.out_dir / "vulnerability-report.json").write_text(
        json.dumps(report_json, indent=2), encoding="utf-8"
    )

    md = []
    title = "## Vulnerability diff since previous scan"
    if args.image:
        title += f" - `{args.image}`"
    md.append(title + "\n")
    total = sum(counts.values())
    count_line = " / ".join(f"{SEVERITY_EMOJI[s]} {s}: {counts[s]}" for s in reversed(SEVERITY_ORDER))
    md.append(f"**Current (>= {args.min_severity}): {total} CVE-level finding(s)** - {count_line}\n")
    md.append(
        "> Counted per (package, version, path, CVE), so this number differs from the "
        "Code Scanning alert count, which is grouped per package (one alert can list "
        "several CVEs).\n"
    )

    if diff is None:
        md.append(
            "\n_No baseline from a previous run was found - this is treated as the "
            "first scan. Diff tracking starts from the next run._\n"
        )
    else:
        md.append(f"\n### \U0001f195 New since last scan ({len(diff['new'])})\n")
        md.append(render_table(diff["new"]))
        md.append(f"\n### ✅ Fixed since last scan ({len(diff['fixed'])})\n")
        md.append(render_table(diff["fixed"]))
        md.append(
            "\n> \"Fixed\" means this exact package+version+path+CVE combination is no "
            "longer present - it does not by itself prove the CVE was resolved rather "
            "than the package being replaced by a still-vulnerable newer version. "
            "Cross-check the \"New\" table above for the same CVE reappearing under a "
            "different package version (see docs/runbook.md section 5).\n"
        )

    md.append("\n### All current findings\n")
    md.append(render_table(current))

    md_text = "\n".join(md)
    (args.out_dir / "vulnerability-report.md").write_text(md_text, encoding="utf-8")

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write("\n" + md_text + "\n")

    if args.baseline:
        args.baseline.parent.mkdir(parents=True, exist_ok=True)
        args.baseline.write_text(json.dumps(current, indent=2), encoding="utf-8")

    print(f"Vulnerability report written to {args.out_dir}")


if __name__ == "__main__":
    main()
