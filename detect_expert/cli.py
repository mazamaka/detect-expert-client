"""Command-line interface for Detect Expert client."""

import argparse
import json
import sys
import os
import logging
from typing import Optional

from .client import DetectExpertClient
from .exceptions import DetectExpertError


def setup_logging(verbose: bool = False) -> None:
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
    )


def get_credentials(args: argparse.Namespace) -> tuple[str, str]:
    """Get credentials from args or environment."""
    email = args.email or os.environ.get("DETECT_EXPERT_EMAIL")
    password = args.password or os.environ.get("DETECT_EXPERT_PASSWORD")

    if not email or not password:
        print("Error: Email and password required.", file=sys.stderr)
        print("Use --email/--password or set DETECT_EXPERT_EMAIL/DETECT_EXPERT_PASSWORD", file=sys.stderr)
        sys.exit(1)

    return email, password


def cmd_check(args: argparse.Namespace) -> int:
    """Run DNS check command."""
    email, password = get_credentials(args)

    client = DetectExpertClient()

    try:
        print(f"🔐 Logging in as {email}...")
        account = client.login(email, password)
        print(f"✅ Authenticated. Balance: ${account.balance:.2f}")

        print(f"\n📤 Starting DNS check for {args.ip}...")

        def on_page(page: int, total: int) -> None:
            if page % 20 == 0:
                print(f"   📄 Page {page}: {total} records")

        result = client.check_dns(
            args.ip,
            wait_seconds=args.wait,
            max_pages=args.max_pages,
            page_delay=args.delay,
        )

        # Fetch with progress
        if not result.records:
            result.records = list(
                client.fetch_results(
                    result.check_id,
                    result.session_id,
                    max_pages=args.max_pages,
                    delay=args.delay,
                    on_page=on_page,
                )
            )

        print(f"\n✅ Found {result.total_records} DNS records")
        print(f"   URL: {result.url}")

        # Save results
        if args.output:
            save_results(result, args.output, args.format)
            print(f"💾 Saved to {args.output}")

        # Show stats
        if result.providers:
            print("\n📊 Top providers:")
            for provider, count in list(result.providers.items())[:5]:
                print(f"   {provider}: {count}")

        # Show sample
        if not args.quiet and result.records:
            print(f"\n📋 Sample records:")
            for record in result.records[:10]:
                print(f"   {record.ip} - {record.provider}")
            if result.total_records > 10:
                print(f"   ... and {result.total_records - 10} more")

        return 0

    except DetectExpertError as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1


def cmd_history(args: argparse.Namespace) -> int:
    """Show check history."""
    email, password = get_credentials(args)

    client = DetectExpertClient()

    try:
        client.login(email, password)
        history = client.get_history(limit=args.limit)

        print(f"📜 Check history ({len(history)} items):\n")
        for i, check in enumerate(history, 1):
            url = f"https://detect.expert/dnscheck/{check['check_id']}/{check['session_id']}"
            print(f"   {i}. {url}")

        return 0

    except DetectExpertError as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1


def cmd_fetch(args: argparse.Namespace) -> int:
    """Fetch results from existing check."""
    email, password = get_credentials(args)

    client = DetectExpertClient()

    try:
        client.login(email, password)

        print(f"📥 Fetching results...")

        def on_page(page: int, total: int) -> None:
            if page % 20 == 0:
                print(f"   📄 Page {page}: {total} records")

        from .models import CheckResult

        result = CheckResult(
            check_id=args.check_id,
            session_id=args.session_id,
            ip_checked="",
        )

        result.records = list(
            client.fetch_results(
                args.check_id,
                args.session_id,
                max_pages=args.max_pages,
                delay=args.delay,
                on_page=on_page,
            )
        )

        print(f"\n✅ Found {result.total_records} DNS records")

        if args.output:
            save_results(result, args.output, args.format)
            print(f"💾 Saved to {args.output}")

        return 0

    except DetectExpertError as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1


def save_results(result, output: str, fmt: str) -> None:
    """Save results to file."""
    if fmt == "json" or output.endswith(".json"):
        with open(output, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, ensure_ascii=False, indent=2)
    elif fmt == "ips" or output.endswith(".txt"):
        with open(output, "w") as f:
            for ip in result.to_ip_list():
                f.write(f"{ip}\n")
    else:
        # CSV
        with open(output, "w") as f:
            f.write("ip,provider,country\n")
            for record in result.records:
                f.write(f"{record.ip},{record.provider},{record.country}\n")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="detect-expert",
        description="Detect Expert DNS Check Client",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    # Auth options
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument(
        "-e", "--email",
        help="Account email (or DETECT_EXPERT_EMAIL env)",
    )
    auth_group.add_argument(
        "-p", "--password",
        help="Account password (or DETECT_EXPERT_PASSWORD env)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Check command
    check_parser = subparsers.add_parser("check", help="Run DNS check")
    check_parser.add_argument("ip", help="IP address to check")
    check_parser.add_argument(
        "-o", "--output",
        help="Output file (json/txt/csv)",
    )
    check_parser.add_argument(
        "-f", "--format",
        choices=["json", "ips", "csv"],
        default="json",
        help="Output format",
    )
    check_parser.add_argument(
        "--wait",
        type=float,
        default=3.0,
        help="Wait seconds after check (default: 3)",
    )
    check_parser.add_argument(
        "--max-pages",
        type=int,
        default=300,
        help="Max pages to fetch (default: 300)",
    )
    check_parser.add_argument(
        "--delay",
        type=float,
        default=0.2,
        help="Delay between requests (default: 0.2)",
    )
    check_parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode",
    )
    check_parser.set_defaults(func=cmd_check)

    # History command
    history_parser = subparsers.add_parser("history", help="Show check history")
    history_parser.add_argument(
        "-l", "--limit",
        type=int,
        default=10,
        help="Max items (default: 10)",
    )
    history_parser.set_defaults(func=cmd_history)

    # Fetch command
    fetch_parser = subparsers.add_parser("fetch", help="Fetch existing check results")
    fetch_parser.add_argument("check_id", help="Check ID")
    fetch_parser.add_argument("session_id", help="Session ID")
    fetch_parser.add_argument(
        "-o", "--output",
        help="Output file",
    )
    fetch_parser.add_argument(
        "-f", "--format",
        choices=["json", "ips", "csv"],
        default="json",
        help="Output format",
    )
    fetch_parser.add_argument(
        "--max-pages",
        type=int,
        default=300,
        help="Max pages",
    )
    fetch_parser.add_argument(
        "--delay",
        type=float,
        default=0.2,
        help="Delay between requests",
    )
    fetch_parser.set_defaults(func=cmd_fetch)

    args = parser.parse_args()

    setup_logging(args.verbose)

    if not args.command:
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
