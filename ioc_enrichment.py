"""
IOC Enrichment Script — Cipher and Counsel
GRC Third-Party Risk Assessment Tool

Purpose:
  Queries threat intelligence APIs to enrich indicators of compromise (IOCs)
  and generate a structured risk report. Demonstrates API integration,
  authentication, and data retrieval for GRC analyst workflows.

Usage:
  python3 ioc_enrichment.py --ip 8.8.8.8
  python3 ioc_enrichment.py --ip 1.1.1.1 --output report.json

APIs Used:
  - AbuseIPDB (free tier) — IP reputation and abuse confidence score
  - GreyNoise Community API (free tier) — internet scanner classification

Author: Cipher and Counsel | www.cipherandcounsel.com
"""

import argparse
import json
import sys
from datetime import datetime, timezone

# Standard library only — no pip install required for basic demo
# For API calls: pip install requests
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ── CONFIGURATION ──────────────────────────────────────
# Replace with your own free API keys
# AbuseIPDB: https://www.abuseipdb.com/account/api
# GreyNoise: https://viz.greynoise.io/account/

ABUSEIPDB_API_KEY  = "YOUR_ABUSEIPDB_KEY_HERE"
GREYNOISE_API_KEY  = "YOUR_GREYNOISE_KEY_HERE"


# ── RISK RATING FRAMEWORK ──────────────────────────────
def calculate_risk_rating(abuse_score, greynoise_classification):
    """
    Maps threat intelligence data to a standardized risk rating.
    Modeled on NIST SP 800-53 risk assessment methodology.

    Risk Levels:
      CRITICAL  — Confirmed malicious activity, immediate action required
      HIGH      — Strong indicators of malicious intent
      MEDIUM    — Suspicious activity, further investigation recommended
      LOW       — Minimal indicators, continue monitoring
      INFO      — No threat indicators detected
    """
    if abuse_score >= 75 or greynoise_classification == "malicious":
        return "CRITICAL", "Confirmed malicious. Block and escalate to Tier 2."
    elif abuse_score >= 50 or greynoise_classification == "malicious":
        return "HIGH", "Strong malicious indicators. Review and consider blocking."
    elif abuse_score >= 25:
        return "MEDIUM", "Suspicious activity detected. Investigate further."
    elif abuse_score > 0 or greynoise_classification == "unknown":
        return "LOW", "Minimal indicators. Add to watchlist and monitor."
    else:
        return "INFO", "No threat indicators. Normal internet traffic."


# ── API QUERY FUNCTIONS ────────────────────────────────
def query_abuseipdb(ip_address):
    """
    Queries AbuseIPDB API for IP reputation data.
    Returns abuse confidence score, country, ISP, and recent reports.

    Authentication: API key passed in request header (X-Auth-Token)
    Rate limit: 1,000 queries per day on free tier
    """
    if not REQUESTS_AVAILABLE:
        return {"error": "requests library not installed. Run: pip install requests"}

    endpoint = "https://api.abuseipdb.com/api/v2/check"
    headers  = {
        "Accept":       "application/json",
        "Key":          ABUSEIPDB_API_KEY,
    }
    params = {
        "ipAddress":    ip_address,
        "maxAgeInDays": "90",
        "verbose":      "",
    }

    try:
        response = requests.get(endpoint, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        return response.json().get("data", {})
    except requests.exceptions.HTTPError as e:
        # Handle common authentication errors
        if response.status_code == 401:
            return {"error": "AbuseIPDB: Invalid API key. Check your credentials."}
        elif response.status_code == 429:
            return {"error": "AbuseIPDB: Rate limit exceeded. Try again tomorrow."}
        return {"error": f"AbuseIPDB HTTP error: {str(e)}"}
    except requests.exceptions.Timeout:
        return {"error": "AbuseIPDB: Request timed out. Check network connectivity."}
    except requests.exceptions.ConnectionError:
        return {"error": "AbuseIPDB: Connection failed. Check network connectivity."}


def query_greynoise(ip_address):
    """
    Queries GreyNoise Community API to classify internet scanners.
    Returns classification: malicious, benign, or unknown.

    Authentication: API key passed in request header (key)
    Rate limit: 50 queries per day on community (free) tier
    """
    if not REQUESTS_AVAILABLE:
        return {"error": "requests library not installed. Run: pip install requests"}

    endpoint = f"https://api.greynoise.io/v3/community/{ip_address}"
    headers  = {"key": GREYNOISE_API_KEY}

    try:
        response = requests.get(endpoint, headers=headers, timeout=10)
        if response.status_code == 404:
            # 404 means the IP is not in GreyNoise's dataset — treat as unknown
            return {"noise": False, "riot": False, "classification": "unknown",
                    "message": "IP not observed by GreyNoise scanners."}
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        if response.status_code == 401:
            return {"error": "GreyNoise: Invalid API key. Check your credentials."}
        elif response.status_code == 429:
            return {"error": "GreyNoise: Rate limit exceeded."}
        return {"error": f"GreyNoise HTTP error: {str(e)}"}
    except requests.exceptions.Timeout:
        return {"error": "GreyNoise: Request timed out."}


# ── REPORT GENERATOR ──────────────────────────────────
def generate_report(ip_address, abuse_data, greynoise_data):
    """
    Produces a structured GRC risk report from enriched IOC data.
    Format modeled on Unit 42 threat intelligence reporting standards.
    """

    # Extract key values with safe defaults
    abuse_score    = abuse_data.get("abuseConfidenceScore", 0)
    country        = abuse_data.get("countryCode", "Unknown")
    isp            = abuse_data.get("isp", "Unknown")
    total_reports  = abuse_data.get("totalReports", 0)
    last_reported  = abuse_data.get("lastReportedAt", "Never")
    domain         = abuse_data.get("domain", "Unknown")

    gn_class       = greynoise_data.get("classification", "unknown")
    gn_noise       = greynoise_data.get("noise", False)
    gn_riot        = greynoise_data.get("riot", False)   # riot = known benign service
    gn_name        = greynoise_data.get("name", "")

    # Calculate risk rating
    risk_level, recommendation = calculate_risk_rating(abuse_score, gn_class)

    # Build structured report
    report = {
        "report_metadata": {
            "generated_at":     datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "indicator_type":   "IPv4",
            "indicator_value":  ip_address,
            "analyst":          "Cipher and Counsel IOC Enrichment Script",
            "framework":        "NIST SP 800-53 RA-3 (Risk Assessment)",
        },
        "indicator_summary": {
            "ip_address":       ip_address,
            "country":          country,
            "isp":              isp,
            "domain":           domain,
        },
        "threat_intelligence": {
            "abuseipdb": {
                "abuse_confidence_score": abuse_score,
                "total_reports_90d":      total_reports,
                "last_reported":          last_reported,
                "source":                 "AbuseIPDB",
            },
            "greynoise": {
                "classification":  gn_class,
                "internet_scanner": gn_noise,
                "known_benign":     gn_riot,
                "entity_name":      gn_name if gn_name else "N/A",
                "source":          "GreyNoise Community",
            },
        },
        "risk_assessment": {
            "risk_level":       risk_level,
            "recommendation":   recommendation,
            "confidence":       "HIGH" if total_reports > 5 else "MEDIUM" if total_reports > 0 else "LOW",
            "escalate":         risk_level in ("CRITICAL", "HIGH"),
        },
    }

    return report


def print_report(report):
    """Formats and prints the risk report to console."""

    meta  = report["report_metadata"]
    ind   = report["indicator_summary"]
    ti    = report["threat_intelligence"]
    risk  = report["risk_assessment"]

    print("\n" + "="*60)
    print("  IOC ENRICHMENT REPORT — CIPHER AND COUNSEL")
    print("  GRC Risk Assessment Tool")
    print("="*60)
    print(f"\n  Generated:    {meta['generated_at']}")
    print(f"  Framework:    {meta['framework']}")
    print(f"\n  INDICATOR:    {ind['ip_address']}")
    print(f"  Country:      {ind['country']}")
    print(f"  ISP:          {ind['isp']}")
    print(f"  Domain:       {ind['domain']}")
    print(f"\n  THREAT INTELLIGENCE:")
    print(f"  AbuseIPDB Score:    {ti['abuseipdb']['abuse_confidence_score']}/100")
    print(f"  Reports (90d):      {ti['abuseipdb']['total_reports_90d']}")
    print(f"  Last Reported:      {ti['abuseipdb']['last_reported']}")
    print(f"  GreyNoise Class:    {ti['greynoise']['classification'].upper()}")
    print(f"  Internet Scanner:   {'Yes' if ti['greynoise']['internet_scanner'] else 'No'}")
    print(f"  Known Benign:       {'Yes' if ti['greynoise']['known_benign'] else 'No'}")
    print(f"\n  {'='*40}")
    print(f"  RISK RATING:    {risk['risk_level']}")
    print(f"  Confidence:     {risk['confidence']}")
    print(f"  Escalate:       {'YES — Notify Tier 2' if risk['escalate'] else 'No'}")
    print(f"  Recommendation: {risk['recommendation']}")
    print("="*60 + "\n")


# ── MAIN ───────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="IOC Enrichment Script — GRC Third-Party Risk Assessment",
        epilog="Example: python3 ioc_enrichment.py --ip 8.8.8.8"
    )
    parser.add_argument("--ip",     required=True, help="IPv4 address to enrich")
    parser.add_argument("--output", help="Optional: save JSON report to file")
    parser.add_argument("--demo",   action="store_true",
                        help="Run in demo mode with mock data (no API keys required)")
    args = parser.parse_args()

    print(f"\n[*] Enriching IOC: {args.ip}")

    if args.demo:
        # Demo mode — returns mock data so the script runs without API keys
        # Useful for demonstrating workflow without exposing credentials
        print("[*] Running in DEMO MODE — mock data returned")
        abuse_data     = {
            "abuseConfidenceScore": 85,
            "countryCode": "RU",
            "isp": "Demo ISP LLC",
            "domain": "demo-malicious.example",
            "totalReports": 47,
            "lastReportedAt": "2026-05-15T12:00:00+00:00"
        }
        greynoise_data = {
            "classification": "malicious",
            "noise": True,
            "riot": False,
            "name": "Demo Threat Actor Infrastructure"
        }
    else:
        print("[*] Querying AbuseIPDB...")
        abuse_data     = query_abuseipdb(args.ip)
        print("[*] Querying GreyNoise...")
        greynoise_data = query_greynoise(args.ip)

    # Check for API errors
    if "error" in abuse_data:
        print(f"[!] AbuseIPDB error: {abuse_data['error']}")
        print("[!] Add your API key to the script or use --demo for mock data")
        sys.exit(1)

    # Generate and display report
    report = generate_report(args.ip, abuse_data, greynoise_data)
    print_report(report)

    # Optionally save JSON report
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
