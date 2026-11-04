#!/usr/bin/env python3
"""
Run Semgrep on OWASP BenchmarkPython and score TPR/FPR.

Level 1 of the benchmark: NO LLM. Measures pure detection quality.
Reads expectedresults-0.1.csv, runs Semgrep once on testcode/,
computes confusion matrix per CWE and overall.

Usage:
    python3 benchmarks/run_semgrep_baseline.py
"""

import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

BENCHMARK_ROOT = Path(__file__).parent / "BenchmarkPython"
TESTCODE = BENCHMARK_ROOT / "testcode"
GROUND_TRUTH = BENCHMARK_ROOT / "expectedresults-0.1.csv"
RESULTS_DIR = Path(__file__).parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)


def load_ground_truth():
    gt = {}
    with open(GROUND_TRUTH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) < 4:
                continue
            name, category, is_vuln, cwe = parts[0], parts[1], parts[2], parts[3]
            gt[name] = {
                "category": category,
                "is_vuln": is_vuln.strip().lower() == "true",
                "cwe": f"CWE-{cwe.strip()}",
            }
    return gt


def run_semgrep(config="auto"):
    """Run Semgrep once on testcode/ and return parsed JSON."""
    cmd = [
        "semgrep",
        f"--config={config}",
        "--quiet",
        "--json",
        "--timeout=60",
        str(TESTCODE),
    ]
    print(f"Running: {' '.join(cmd)}", file=sys.stderr)
    print("Expected duration: 10-30 min for ~1230 files", file=sys.stderr)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    if not result.stdout:
        print(f"Semgrep stderr: {result.stderr[:2000]}", file=sys.stderr)
        sys.exit(1)
    return json.loads(result.stdout)


def score(gt, semgrep_results):
    detected = set()
    for f in semgrep_results.get("results", []):
        name = Path(f.get("path", "")).stem
        detected.add(name)

    overall = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    per_cwe = defaultdict(lambda: {"tp": 0, "fp": 0, "tn": 0, "fn": 0})

    for name, info in gt.items():
        cwe = info["cwe"]
        is_vuln = info["is_vuln"]
        is_detected = name in detected

        if is_vuln and is_detected:
            overall["tp"] += 1; per_cwe[cwe]["tp"] += 1
        elif is_vuln and not is_detected:
            overall["fn"] += 1; per_cwe[cwe]["fn"] += 1
        elif not is_vuln and is_detected:
            overall["fp"] += 1; per_cwe[cwe]["fp"] += 1
        else:
            overall["tn"] += 1; per_cwe[cwe]["tn"] += 1

    return overall, dict(per_cwe)


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
    print("Loading ground truth...", file=sys.stderr)
    gt = load_ground_truth()
    print(f"  {len(gt)} test cases", file=sys.stderr)

    config = sys.argv[1] if len(sys.argv) > 1 else "auto"
    print(f"Running Semgrep with --config={config}...", file=sys.stderr)
    results = run_semgrep(config)
    print(f"  {len(results.get('results', []))} raw findings", file=sys.stderr)

    overall, per_cwe = score(gt, results)
    overall_m = metrics(overall)

    output = {
        "config": config,
        "total_cases": len(gt),
        "overall": overall_m,
        "per_cwe": {cwe: metrics(cm) for cwe, cm in sorted(per_cwe.items())},
    }
    out_path = RESULTS_DIR / f"semgrep_baseline_{config.replace('/', '_')}.json"
    out_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"\nResults written to {out_path}", file=sys.stderr)

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