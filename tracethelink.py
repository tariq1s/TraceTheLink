from __future__ import annotations

import argparse
import sys

from core.analyzer import DEFAULT_MAX_REDIRECTS, DEFAULT_TIMEOUT, analyze_batch, analyze_url, read_url_file
from core.reporting import format_output, save_output


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="TraceTheLink: practical URL and redirect triage for security analysts."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--url", help="Analyze a single URL.")
    source.add_argument("--file", help="Analyze URLs from a text file, one per line.")
    parser.add_argument(
        "--output",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format for terminal and saved report.",
    )
    parser.add_argument("--save", help="Save the generated report to a file.")
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"HTTP timeout in seconds. Default: {DEFAULT_TIMEOUT}",
    )
    parser.add_argument(
        "--max-redirects",
        type=int,
        default=DEFAULT_MAX_REDIRECTS,
        help=f"Maximum redirect depth. Default: {DEFAULT_MAX_REDIRECTS}",
    )
    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="Allow localhost, private, internal, and metadata targets.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.url:
            results = [
                analyze_url(
                    args.url,
                    timeout=args.timeout,
                    max_redirects=args.max_redirects,
                    allow_private=args.allow_private,
                )
            ]
        else:
            urls = read_url_file(args.file)
            if not urls:
                raise ValueError("No URLs found in the input file.")
            results = analyze_batch(
                urls,
                timeout=args.timeout,
                max_redirects=args.max_redirects,
                allow_private=args.allow_private,
            )
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    content = format_output(results, args.output)
    print(content)

    if args.save:
        try:
            save_output(content, args.save)
        except OSError as exc:
            print(f"Error saving report: {exc}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
