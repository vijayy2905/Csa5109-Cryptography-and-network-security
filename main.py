"""
main.py
Runs the complete Assignment 5 demonstration (hash evaluation, signature
evaluation, end-to-end pipeline) and saves structured results to results.json
for use in generating the report's tables and charts.
"""

import json
import io
import contextlib

from hash_eval import run_hash_evaluation
from signature_eval import run_signature_evaluation
from pipeline import run_pipeline_demo


def capture(fn):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        result = fn()
    return result, buf.getvalue()


def main():
    all_output = []

    hash_results, out1 = capture(run_hash_evaluation)
    print(out1)
    all_output.append(("HASH EVALUATION", out1))

    sig_results, out2 = capture(run_signature_evaluation)
    print(out2)
    all_output.append(("SIGNATURE EVALUATION", out2))

    pipeline_results, out3 = capture(run_pipeline_demo)
    print(out3)
    all_output.append(("END-TO-END PIPELINE", out3))

    with open("results.json", "w") as f:
        json.dump({
            "hash_results": hash_results,
            "signature_results": sig_results,
            "pipeline_results": [(label, o) for label, o in pipeline_results],
        }, f, indent=2)

    with open("console_output.txt", "w") as f:
        for title, text in all_output:
            f.write(f"\n{'#'*80}\n# {title}\n{'#'*80}\n")
            f.write(text)

    print("\n\n[Saved results.json and console_output.txt]")


if __name__ == "__main__":
    main()
