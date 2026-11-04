#!/usr/bin/env python3
"""
Run the full pipeline (Semgrep + gitleaks + LLM verify) on the subset
and compare verdicts with ground truth.

Level 2 of the benchmark: includes LLM verification.
Runs orchestrator.py on subset/testcode/, reads the resulting JSON report,
compares against subset_ground_truth.json.

Usage:
    python3 benchmarks/run_llm_subset.py
"""

import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

BENCHMARK_DIR = Path(__file__).parent
SUBSET_DIR = BENCHMARK_DIR / "subset"
SUBSET_GT = BENCHMARK_DIR / "subset_ground_truth.json"
PROJECT_ROOT = BENCHMARK_DIR.parent
ORCHESTRATOR = PROJECT_ROOT / "orchestrator.py"
RESULTS_DIR = BENCHMARK_DIR / "results"
RESULTS_DIR.mkdir(exist_ok=True)


def ensure_python_stack_marker():
    marker = SUBSET_DIR / "requirements.txt"
    if not marker.exists():
        marker.write_text("# OWASP BenchmarkPython subset\n")


def run_pipeline():
    target = str(SUBSET_DIR / "testcode")
    cmd = [
        sys.executable, str(ORCHESTRATOR), target,
        "--max", "300",
        "--min-severity", "INFO",
    ]
    print(f"Running: {' '.join(cmd)}", file=sys.stderr)
    print("Expected duration: 15-25 min for 60 cases at ~30s/finding",
          file=sys.stderr)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
    print(result.stdout[-3000:], file=sys.stderr)
    if result.returncode != 0:
        print(f"Pipeline failed:\n{result.stderr[:2000]}", file=sys.stderr)
        sys.exit(1)
    reports = sorted((PROJECT_ROOT / "reports").glob("report_*.json"))
    if not reports:
        print("No report found", file=sys.stderr)
        sys.exit(1)
    print(f"Using report: {reports[-1].name}", file=sys.stderr)
    return json.loads(reports[-1].read_text(encoding="utf-8"))


def evaluate(gt, report):
    by_file = defaultdict(list)
    for f in report["findings"]:
        filename = Path(f["file"]).stem
        by_file[filename].append(f)

    overall = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    per_cwe = defaultdict(lambda: {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
    per_case = []

    for name, info in gt.items():
        cwe = info["cwe"]
        is_vuln = info["is_vuln"]
        findings = by_file.get(name, [])

        has_tp = any(f["llm"]["verdict"] == "true_positive" for f in findings)

        per_case.append({
            "test_name": name,
            "cwe": cwe,
            "category": info["category"],
            "is_vuln_gt": is_vuln,
            "n_findings": len(findings),
            "verdicts": [f["llm"]["verdict"] for f in findings],
            "detected": has_tp,
        })

        if is_vuln and has_tp:
            overall["tp"] += 1; per_cwe[cwe]["tp"] += 1
        elif is_vuln and not has_tp:
            overall["fn"] += 1; per_cwe[cwe]["fn"] += 1
        elif not is_vuln and has_tp:
            overall["fp"] += 1; per_cwe[cwe]["fp"] += 1
        else:
            overall["tn"] += 1; per_cwe[cwe]["tn"] += 1

    return overall, dict(per_cwe), per_case


def metrics(cm):
    tp, fp, tn, fn = cm["tp"], cm["fp"], cm["tn"], cm["fn"]
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "tpr": round(tpr, 4), "fpr": round(fpr, 4),
        "precision": round(precision, 4),
        "score": round(tpr - fpr, 4),
    }


def main():
    ensure_python_stack_marker()
    if not SUBSET_GT.exists():
        print("Run select_subset.py first", file=sys.stderr)
        sys.exit(1)

    gt = json.loads(SUBSET_GT.read_text(encoding="utf-8"))
    print(f"Subset: {len(gt)} cases", file=sys.stderr)

    report = run_pipeline()
    overall, per_cwe, per_case = evaluate(gt, report)
    overall_m = metrics(overall)

    output = {
        "overall": overall_m,
        "per_cwe": {cwe: metrics(cm) for cwe, cm in sorted(per_cwe.items())},
        "per_case": per_case,
    }
    out_path = RESULTS_DIR / "llm_subset.json"
    out_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"\nResults: {out_path}", file=sys.stderr)

    print("\n=== Overall ===")
    print(f"  TP={overall_m['tp']} FP={overall_m['fp']} "
          f"TN={overall_m['tn']} FN={overall_m['fn']}")
    print(f"  TPR={overall_m['tpr']} FPR={overall_m['fpr']} "
          f"Score={overall_m['score']} Precision={overall_m['precision']}")

    print("\n=== Per CWE ===")
    for cwe, cm in sorted(per_cwe.items()):
        m = metrics(cm)
        print(f"  {cwe:10s} TPR={m['tpr']:.2f} FPR={m['fpr']:.2f} "
              f"TP={m['tp']:3d} FP={m['fp']:3d} FN={m['fn']:3d} TN={m['tn']:3d}")


if __name__ == "__main__":
    main()