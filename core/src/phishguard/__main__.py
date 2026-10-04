"""CLI interface for PhishGuard AI (TASK T2.7)."""

from __future__ import annotations

import argparse
import json
import sys

from phishguard_core.inference import get_detector
from phishguard_core.safety import defang


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="phishguard",
        description="PhishGuard AI - AI-powered phishing and malicious URL detector",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a URL through the fast detection path")
    scan_parser.add_argument("url", type=str, help="Web address (URL) to evaluate")
    scan_parser.add_argument("--json", action="store_true", help="Output full verdict as JSON")

    args = parser.parse_args()

    if args.command == "scan":
        detector = get_detector()
        result = detector.scan(args.url)

        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
            return

        defanged_display = defang(result.url_canonical or args.url)
        print("\n" + "=" * 60)
        print(" PhishGuard AI — Analysis Result")
        print("=" * 60)
        print(f" URL:            {defanged_display}")
        print(f" Domain:         {result.registered_domain or 'N/A'}")
        print(f" Verdict:        {result.verdict.upper()}")
        print(f" Risk Score:     {result.risk_score} / 100  (p={result.probability:.4f})")
        print(f" Confidence:     {result.confidence.capitalize()}")
        print(f" Model Version:  {result.model_version}")
        print(f" Latency:        {result.latency_ms} ms")

        if result.reasons:
            print("\n Key Signals Identified:")
            for r in result.reasons:
                print(f"   [{r.severity.upper()}] {r.text}")
        elif result.verdict == "no_threat_found":
            print("\n Details: No obvious phishing or scam indicators found.")

        print("=" * 60 + "\n")
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
