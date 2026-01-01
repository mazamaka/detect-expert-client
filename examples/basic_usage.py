#!/usr/bin/env python3
"""
Basic usage example for Detect Expert client.

This example demonstrates how to:
1. Authenticate with detect.expert
2. Run a DNS check for an IP address
3. Process and save results
"""

import json
import os
from detect_expert import DetectExpertClient, DetectExpertError


def main():
    # Get credentials from environment or use defaults
    email = os.environ.get("DETECT_EXPERT_EMAIL", "your@email.com")
    password = os.environ.get("DETECT_EXPERT_PASSWORD", "your_password")

    # Create client
    client = DetectExpertClient()

    try:
        # Login
        print("🔐 Logging in...")
        account = client.login(email, password)
        print(f"✅ Authenticated! Balance: ${account.balance:.2f}")

        # Run DNS check
        ip_to_check = "8.8.8.8"  # Google DNS
        print(f"\n📤 Checking DNS for {ip_to_check}...")

        result = client.check_dns(
            ip_to_check,
            wait_seconds=3.0,  # Wait for results
            max_pages=100,     # Limit pages
        )

        # Show results
        print(f"\n✅ Check completed!")
        print(f"   Total records: {result.total_records}")
        print(f"   Unique IPs: {len(result.unique_ips)}")
        print(f"   URL: {result.url}")

        # Show provider stats
        print("\n📊 Providers:")
        for provider, count in list(result.providers.items())[:5]:
            print(f"   {provider}: {count}")

        # Show sample records
        print("\n📋 Sample records:")
        for record in result.records[:5]:
            print(f"   {record.ip} | {record.provider} | {record.country}")

        # Save to JSON
        output_file = "dns_results.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, ensure_ascii=False, indent=2)
        print(f"\n💾 Results saved to {output_file}")

        # Save IPs only
        ip_file = "dns_ips.txt"
        with open(ip_file, "w") as f:
            for ip in result.to_ip_list():
                f.write(f"{ip}\n")
        print(f"💾 IPs saved to {ip_file}")

    except DetectExpertError as e:
        print(f"❌ Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
