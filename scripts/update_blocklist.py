"""
Fetches the Hagezi DNS light blocklist and Cloudflare Radar top 1M domains,
filters to their intersection, and writes the result to blocklists/light.txt.
Exits with code 1 on any error.
"""

import urllib.request
import urllib.error
import csv
import sys
import os
import io

BLOCKLIST_URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/domains/light.txt"
CF_RADAR_URL = "https://api.cloudflare.com/client/v4/radar/datasets/ranking_top_1000000"
OUTPUT_FILE = "public/blocklists/light.txt"


def fetch_blocklist():
    print(f"Fetching blocklist from: {BLOCKLIST_URL}")
    try:
        with urllib.request.urlopen(BLOCKLIST_URL, timeout=60) as response:
            if response.status != 200:
                print(f"ERROR: Blocklist fetch returned HTTP {response.status}", file=sys.stderr)
                sys.exit(1)
            raw = response.read().decode("utf-8")
    except urllib.error.URLError as e:
        print(f"ERROR: Failed to fetch blocklist: {e}", file=sys.stderr)
        sys.exit(1)

    domains = set()
    for line in raw.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            domains.add(line.lower())

    if not domains:
        print("ERROR: Parsed blocklist is empty.", file=sys.stderr)
        sys.exit(1)

    print(f"Parsed {len(domains)} domains from blocklist.")
    return domains


def fetch_cf_top_domains(api_token):
    print(f"Fetching Cloudflare Radar top 1M domains from: {CF_RADAR_URL}")

    # Use a no-redirect opener so we can detect a redirect and fetch the
    # destination URL *without* the Authorization header.  Cloudflare's
    # endpoint may redirect to a signed R2/S3 URL; forwarding the auth header
    # to that URL causes a 403 signature-mismatch error.
    no_redirect_opener = urllib.request.build_opener(
        urllib.request.HTTPErrorProcessor()  # suppresses raising on 3xx
    )

    request = urllib.request.Request(
        CF_RADAR_URL,
        headers={"Authorization": f"Bearer {api_token}"},
    )
    try:
        response = no_redirect_opener.open(request, timeout=60)
        status = response.status
        location = response.headers.get("Location")
        body = response.read()
    except urllib.error.URLError as e:
        print(f"ERROR: Failed to fetch Cloudflare Radar dataset: {e}", file=sys.stderr)
        sys.exit(1)

    if status in (301, 302, 303, 307, 308) and location:
        # Follow the redirect without the Authorization header
        print(f"Following redirect to signed URL...")
        try:
            with urllib.request.urlopen(location, timeout=120) as r2:
                if r2.status != 200:
                    print(f"ERROR: Signed URL download returned HTTP {r2.status}", file=sys.stderr)
                    sys.exit(1)
                raw = r2.read().decode("utf-8")
        except urllib.error.URLError as e:
            print(f"ERROR: Failed to download from redirect URL: {e}", file=sys.stderr)
            sys.exit(1)
    elif status == 200:
        raw = body.decode("utf-8")
    else:
        print(f"ERROR: Cloudflare API returned HTTP {status}", file=sys.stderr)
        sys.exit(1)

    # Dataset is a CSV: rank,domain (with optional header row)
    domains = set()
    reader = csv.reader(io.StringIO(raw))
    for row in reader:
        if not row:
            continue
        # Skip header row if present (e.g. "rank,domain")
        if row[0].strip().lower() in ("rank", "#"):
            continue
        # Each row: [rank, domain] or just [domain]
        if len(row) >= 2:
            domain = row[1].strip().lower()
        else:
            domain = row[0].strip().lower()
        if domain:
            domains.add(domain)

    if not domains:
        print("ERROR: Cloudflare top domains dataset is empty or could not be parsed.", file=sys.stderr)
        sys.exit(1)

    print(f"Fetched {len(domains)} top domains from Cloudflare Radar dataset.")
    return domains


def main():
    api_token = os.environ.get("CF_API_TOKEN", "").strip()
    if not api_token:
        print("ERROR: CF_API_TOKEN environment variable is not set or is empty.", file=sys.stderr)
        sys.exit(1)

    blocklist = fetch_blocklist()
    top_domains = fetch_cf_top_domains(api_token)

    filtered = sorted(blocklist & top_domains)
    print(f"Filtered result: {len(filtered)} domains (intersection of blocklist and top 1M domains).")

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(filtered))
        if filtered:
            f.write("\n")

    print(f"Wrote {len(filtered)} domains to {OUTPUT_FILE}.")


if __name__ == "__main__":
    main()
