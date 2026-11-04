#!/usr/bin/env python3
"""
Select a stratified subset of benchmark cases for LLM verification.

Goal: ~60 cases balanced across CWEs and vulnerable/secure.
Copies files to benchmarks/subset/testcode/ and writes ground truth.

Usage:
    python3 benchmarks/select_subset.py
"""

import json
import random
import shutil
from collections import defaultdict
from pathlib import Path

BENCHMARK_ROOT = Path(__file__).parent / "BenchmarkPython"
TESTCODE = BENCHMARK_ROOT / "testcode"
GROUND_TRUTH = BENCHMARK_ROOT / "expectedresults-0.1.csv"
SUBSET_DIR = Path(__file__).parent / "subset"
SUBSET_GT = Path(__file__).parent / "subset_ground_truth.json"

N_PER_CWE_VULN = 3
N_PER_CWE_SECURE = 3


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


def main():
    random.seed(42)
    gt = load_ground_truth()

    grouped = defaultdict(list)
    for name, info in gt.items():
        grouped[(info["cwe"], info["is_vuln"])].append(name)

    selected = []
    for (cwe, is_vuln), names in grouped.items():
        n = N_PER_CWE_VULN if is_vuln else N_PER_CWE_SECURE
        selected.extend(random.sample(names, min(n, len(names))))

    if SUBSET_DIR.exists():
        shutil.rmtree(SUBSET_DIR)
    (SUBSET_DIR / "testcode").mkdir(parents=True)

    subset_gt = {}
    for name in selected:
        src = TESTCODE / f"{name}.py"
        if not src.exists():
            continue
        dst = SUBSET_DIR / "testcode" / f"{name}.py"
        shutil.copy2(src, dst)
        subset_gt[name] = gt[name]

    SUBSET_GT.write_text(json.dumps(subset_gt, indent=2), encoding="utf-8")

    n_vuln = sum(1 for i in subset_gt.values() if i["is_vuln"])
    n_secure = len(subset_gt) - n_vuln
    print(f"Selected {len(subset_gt)} cases -> {SUBSET_DIR}")
    print(f"  Vulnerable: {n_vuln}")
    print(f"  Secure: {n_secure}")

    by_cwe = defaultdict(int)
    for info in subset_gt.values():
        by_cwe[info["cwe"]] += 1
    print("\nBreakdown by CWE:")
    for cwe, count in sorted(by_cwe.items()):
        print(f"  {cwe:10s} {count} cases")


if __name__ == "__main__":
    main()