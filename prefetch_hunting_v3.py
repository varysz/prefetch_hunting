import base64
import re
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

# Output directory and file with timestamp
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_DIR = f"Output_{TIMESTAMP}"
os.makedirs(OUTPUT_DIR, exist_ok=True)
OUTPUT_FILE = os.path.join(OUTPUT_DIR, f"results_dom_scanner_urlscan_{TIMESTAMP}.txt")

# Collect findings across all domains for summary
all_findings = {}
injected_domains = set()
injected_async_domains = {}  # domain -> set of decoded script names


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


def load_known_good_async(filepath="known_good_async.txt"):
    """Load known good domains to exclude from async script results."""
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


def decode_base64_segment(segment):
    """Try to decode a base64 segment, return decoded string or None on failure."""
    try:
        padding = 4 - len(segment) % 4
        padded = segment + "=" * (padding % 4)
        return base64.b64decode(padded).decode("utf-8", errors="replace")
    except Exception:
        return None


def search_async_scripts(dom, known_good_async, current_domain):
    """Find suspicious async script tags where a path segment is base64-encoded.

    Skips known good domains. Flags only when a full path segment (between slashes)
    matches the base64 pattern — decodes it and includes the result in findings.
    """
    lines = dom.splitlines()
    suspicious = []

    for line_number, line in enumerate(lines, start=1):
        line_lower = line.lower()
        if "<script" not in line_lower or "async" not in line_lower or "src=" not in line_lower:
            continue

        # Extract src value
        src = ""
        parts = line.split("src=")
        if len(parts) > 1:
            after = parts[1].strip()
            if after.startswith('"'):
                src = after.split('"')[1]
            elif after.startswith("'"):
                src = after.split("'")[1]

        if not src:
            continue

        # Skip self-references
        if current_domain.lower() in src.lower():
            continue

        # Skip known good domains
        src_clean = src.replace("https://", "").replace("http://", "")
        src_domain = src_clean.split("/")[0].lower()
        if any(good in src_domain for good in known_good_async):
            continue

        # Check each path segment — flag only if a whole segment is base64
        path_segments = "/".join(src_clean.split("/")[1:]).split("/")
        decoded_values = []
        for segment in path_segments:
            if re.fullmatch(r'[A-Za-z0-9+/]{16,}={0,2}', segment):
                decoded = decode_base64_segment(segment)
                if decoded:
                    decoded_values.append(decoded)

        if decoded_values:
            suspicious.append((line_number, src, decoded_values))

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
    global all_findings, injected_domains, injected_async_domains

    if not url.startswith("http"):
        url = "https://" + url

    domain_label = url.replace("https://", "").replace("http://", "").rstrip("/")
    findings = {"prefetch": [], "matches": [], "async_scripts": []}

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
    suspicious_prefetch = search_prefetch(dom, known_good, domain_label)
    for line_number, href in suspicious_prefetch:
        findings["prefetch"].append(href)
        domain = extract_domain_from_href(href)
        if domain:
            injected_domains.add(domain)

    # Step 5: Suspicious async script tags
    known_good_async = load_known_good_async()
    suspicious_async = search_async_scripts(dom, known_good_async, domain_label)
    for line_number, src, decoded_values in suspicious_async:
        findings["async_scripts"].append((src, decoded_values))
        domain = extract_domain_from_href(src)
        if domain:
            if domain not in injected_async_domains:
                injected_async_domains[domain] = set()
            injected_async_domains[domain].update(decoded_values)

    # Step 6: Only write output if there are findings
    if findings["prefetch"] or findings["matches"] or findings["async_scripts"]:
        all_findings[domain_label] = findings
        write_result(f"\n{domain_label}")

        for href in findings["prefetch"]:
            write_result(f"  🔗 Prefetch: {href}")

        for src, decoded_values in findings["async_scripts"]:
            for decoded in decoded_values:
                write_result(f"  ⚠️  Async script [base64 → {decoded}]: {src}")

        for term, line_number, line in findings["matches"]:
            write_result(f"  🎯 Match: \"{term}\" on line {line_number}")

    else:
        print(f"  ✅ {domain_label} — clean, skipping.")

    time.sleep(3)


# --- Run it ---
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("\nUsage: python3 prefetch_hunting_v3.py <domains_file> <searchterms_file>")
        print("Example: python3 prefetch_hunting_v3.py domains.txt searchterms.txt\n")
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
        write_result(f"\n🚨 Unique injected prefetch domains ({len(injected_domains)}):")
        for d in sorted(injected_domains):
            write_result(f"   → {d}")

    if injected_async_domains:
        write_result(f"\n🚨 Unique injected async script domains ({len(injected_async_domains)}):")
        for d in sorted(injected_async_domains):
            for script in sorted(injected_async_domains[d]):
                write_result(f"   → {d}\t script injected: {script}")

    write_result("=" * 50)
    write_result(f"📄 Results saved to: {OUTPUT_FILE}")

    # --- Write deduplicated prefetch domains file ---
    if injected_domains:
        PREFETCH_FILE = os.path.join(OUTPUT_DIR, f"results_prefetch_domains_{TIMESTAMP}.txt")
        with open(PREFETCH_FILE, "w") as f:
            for d in sorted(injected_domains):
                f.write(d + "\n")
        print(f"🚨 Prefetch domains saved to: {PREFETCH_FILE}")

    # --- Write deduplicated async script domains file ---
    if injected_async_domains:
        ASYNC_FILE = os.path.join(OUTPUT_DIR, f"results_async_domains_{TIMESTAMP}.txt")
        with open(ASYNC_FILE, "w") as f:
            for d in sorted(injected_async_domains):
                for script in sorted(injected_async_domains[d]):
                    f.write(f"{d}\t script injected: {script}\n")
        print(f"🚨 Async script domains saved to: {ASYNC_FILE}")
