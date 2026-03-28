import requests
import sys
import time
import os
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")

if not URLSCAN_API_KEY:
    print("❌ No API key found! Create a .env file with URLSCAN_API_KEY=yourkey")
    sys.exit(1)

HEADERS = {
    "api-key": URLSCAN_API_KEY,
    "Content-Type": "application/json"
}

# Output file with timestamp
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_FILE = f"results_dom_scanner_urlscan_{TIMESTAMP}.txt"

# Collect findings across all domains for summary
all_findings = {}
injected_domains = set()


def write_result(line):
    """Write a line to both console and output file."""
    print(line)
    with open(OUTPUT_FILE, "a") as f:
        f.write(line + "\n")


def load_file(filepath):
    """Load non-empty lines from a text file."""
    try:
        with open(filepath, "r") as f:
            lines = [line.strip() for line in f if line.strip()]
        return lines
    except FileNotFoundError:
        print(f"❌ File not found: {filepath}")
        sys.exit(1)


def quick_check(url):
    """Check if a recent scan already exists for this URL (last 240 hours)."""
    domain = url.replace("https://", "").replace("http://", "").rstrip("/")
    print(f"🔎 Checking existing scans for: {domain}")

    response = requests.get(
        f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=5",
        headers=HEADERS
    )

    if response.status_code != 200:
        print(f"⚠️  Could not search existing scans, will submit new scan.")
        return None

    data = response.json()
    results = data.get("results", [])

    if not results:
        print(f"ℹ️  No existing scans found.")
        return None

    latest = results[0]
    scan_time_str = latest.get("task", {}).get("time", "")

    if scan_time_str:
        scan_time = datetime.strptime(scan_time_str[:19], "%Y-%m-%dT%H:%M:%S")
        age_hours = (datetime.utcnow() - scan_time).total_seconds() / 3600

        if age_hours < 240:
            scan_id = latest.get("_id") or latest.get("task", {}).get("uuid")
            print(f"✅ Found recent scan from {age_hours:.1f} hours ago — reusing it!")
            return scan_id
        else:
            print(f"ℹ️  Most recent scan is {age_hours:.1f} hours old — submitting fresh scan.")
            return None

    return None


def submit_scan(url):
    """Submit a new scan to urlscan.io."""
    print(f"🔍 Submitting to urlscan.io: {url}")
    response = requests.post(
        "https://urlscan.io/api/v1/scan",
        headers=HEADERS,
        json={
            "url": url,
            "visibility": "public",
            "country": "nl",
            "customagent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
    )
    data = response.json()

    if "uuid" not in data:
        print(f"❌ Failed to submit: {data}")
        return None

    scan_id = data["uuid"]
    print(f"✅ Submitted! ID: {scan_id}")
    return scan_id


def wait_for_scan(scan_id):
    """Poll until scan is complete."""
    print("⏳ Waiting for scan", end="", flush=True)
    time.sleep(10)

    for _ in range(24):
        response = requests.get(
            f"https://urlscan.io/api/v1/result/{scan_id}/",
            headers=HEADERS
        )
        if response.status_code == 200:
            print(" ✅ Done!")
            return response.json()
        elif response.status_code == 404:
            print(".", end="", flush=True)
            time.sleep(5)
        else:
            print(f"\n❌ Unexpected status: {response.status_code}")
            return None

    print("\n❌ Scan timed out.")
    return None


def fetch_dom(scan_id):
    """Fetch the DOM snapshot for a scan."""
    response = requests.get(
        f"https://urlscan.io/dom/{scan_id}/",
        headers=HEADERS
    )
    if response.status_code == 200:
        return response.text
    else:
        print(f"❌ Could not fetch DOM: {response.status_code}")
        return None


def search_dom(dom, search_terms):
    """Search DOM for multiple terms."""
    lines = dom.splitlines()
    results = {}

    for term in search_terms:
        matches = []
        for line_number, line in enumerate(lines, start=1):
            if term.lower() in line.lower():
                matches.append((line_number, line.strip()))
        if matches:
            results[term] = matches

    return results


def load_known_good(filepath="known_good_prefetch.txt"):
    """Load known good domains to exclude from prefetch results."""
    try:
        with open(filepath, "r") as f:
            return [line.strip().lower() for line in f
                    if line.strip() and not line.strip().startswith("#")]
    except FileNotFoundError:
        return []


def search_prefetch(dom, known_good, current_domain):
    """Find suspicious prefetch link tags, excluding known good domains and self-references."""
    lines = dom.splitlines()
    suspicious = []

    for line_number, line in enumerate(lines, start=1):
        if "<link" in line.lower() and "prefetch" in line.lower() and 'href=' in line.lower():
            if not any(good in line.lower() for good in known_good):
                if current_domain.lower() not in line.lower():  # skip self-references
                    href = ""
                    parts = line.split('href=')
                    if len(parts) > 1:
                        href = parts[1].split('"')[1] if '"' in parts[1] else parts[1].split("'")[1]
                    suspicious.append((line_number, href or line.strip()))

    return suspicious


def extract_domain_from_href(href):
    """Pull just the domain out of a full URL for the summary set."""
    href = href.strip()
    # Skip empty or malformed hrefs
    if not href or href.startswith("<") or len(href) < 4:
        return None
    href = href.replace("https://", "").replace("http://", "").lstrip("/")
    domain = href.split("/")[0].strip()
    # Must look like a real domain (contains a dot, no spaces, no HTML)
    if "." not in domain or " " in domain or "<" in domain:
        return None
    return domain


def scan_domain(url, search_terms):
    """Full scan pipeline for a single domain — clean focused output."""
    global all_findings, injected_domains

    if not url.startswith("http"):
        url = "https://" + url

    domain_label = url.replace("https://", "").replace("http://", "").rstrip("/")
    findings = {"prefetch": [], "matches": []}

    # Step 1: Quick check or fresh scan
    scan_id = quick_check(url)

    if not scan_id:
        scan_id = submit_scan(url)
        if not scan_id:
            print(f"❌ Could not obtain scan ID for {domain_label} — skipping.")
            return

        scan_result = wait_for_scan(scan_id)
        if not scan_result:
            print(f"❌ Scan did not complete for {domain_label} — skipping.")
            return
    else:
        response = requests.get(
            f"https://urlscan.io/api/v1/result/{scan_id}/",
            headers=HEADERS
        )
        if response.status_code != 200:
            scan_id = submit_scan(url)
            if not scan_id:
                return
            scan_result = wait_for_scan(scan_id)
            if not scan_result:
                return
        else:
            scan_result = response.json()

    # Step 2: Fetch DOM
    dom = fetch_dom(scan_id)
    if not dom:
        print(f"❌ DOM not available for {domain_label} — skipping.")
        return

    # Step 3: Search term matches
    term_results = search_dom(dom, search_terms)
    for term, matches in term_results.items():
        for line_number, line in matches:
            findings["matches"].append((term, line_number, line[:200]))

    # Step 4: Suspicious prefetch tags
    known_good = load_known_good()
    # suspicious_prefetch = search_prefetch(dom, known_good)
    suspicious_prefetch = search_prefetch(dom, known_good, domain_label)
    for line_number, href in suspicious_prefetch:
        findings["prefetch"].append(href)
        domain = extract_domain_from_href(href)
        if domain:
            injected_domains.add(domain)

    # Step 5: Only write output if there are findings
    if findings["prefetch"] or findings["matches"]:
        all_findings[domain_label] = findings
        write_result(f"\n{domain_label}")

        for href in findings["prefetch"]:
            write_result(f"  🔗 Prefetch: {href}")

        for term, line_number, line in findings["matches"]:
            write_result(f"  🎯 Match: \"{term}\" on line {line_number}")

    else:
        print(f"  ✅ {domain_label} — clean, skipping.")

    time.sleep(3)


# --- Run it ---
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("\nUsage: python3 dom_scanner_urlscan3.py <domains_file> <searchterms_file>")
        print("Example: python3 dom_scanner_urlscan3.py domains.txt searchterms.txt\n")
        sys.exit(1)

    domains_file = sys.argv[1]
    terms_file = sys.argv[2]

    domains = load_file(domains_file)
    search_terms = load_file(terms_file)

    print(f"🔐 DOM Scanner v3 — urlscan.io")
    print(f"📋 {len(domains)} domains | 🔎 {len(search_terms)} search terms")
    print(f"🚀 Starting...\n")

    for domain in domains:
        scan_domain(domain, search_terms)

    # --- Clean summary output ---
    write_result("\n" + "=" * 50)
    write_result(f"📊 Summary: {len(all_findings)} domain(s) with findings out of {len(domains)} scanned")

    if injected_domains:
        write_result(f"\n🚨 Unique injected domains ({len(injected_domains)}):")
        for d in sorted(injected_domains):
            write_result(f"   → {d}")

    write_result("=" * 50)
    write_result(f"📄 Results saved to: {OUTPUT_FILE}")

    # --- Write deduplicated prefetch domains file ---
    if injected_domains:
        PREFETCH_FILE = f"results_prefetch_domains_{TIMESTAMP}.txt"
        with open(PREFETCH_FILE, "w") as f:
            for d in sorted(injected_domains):
                f.write(d + "\n")
        print(f"🚨 Prefetch domains saved to: {PREFETCH_FILE}")
