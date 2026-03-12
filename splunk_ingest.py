"""
splunk_ingest.py
----------------
Automated Splunk Ingestion Pipeline
Cyber Security Analysis — Threat Detection with Splunk
Author: Lucas Camargo
Year:   2026

ETHICAL USE NOTICE:
This tool is for educational and authorised security operations only.
Deploying this pipeline against Splunk instances you do not own or have
explicit written permission to access is illegal under the Australian
Criminal Code Act 1995 (Cth) — s477.1.

OVERVIEW:
Polls a CSV data source every 5 minutes (configurable via POLL_INTERVAL), converts events
to JSON, and sends them into Splunk via the HTTP Event Collector (HEC).
"""

import json
import os
import sys
import time
import logging
import hashlib
import csv
import random
from datetime import datetime, timezone, timedelta
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError


# ── 1. Configuration ─────────────────────────────────────────────────────────

# Splunk HEC endpoint — update to match your Splunk instance
SPLUNK_HOST     = "localhost"
SPLUNK_PORT     = 8088
SPLUNK_INDEX    = "security"
SPLUNK_TOKEN    = os.environ.get("SPLUNK_HEC_TOKEN", "YOUR-HEC-TOKEN-HERE")

# Use HTTP for local lab only — always use HTTPS in production
# Set SPLUNK_USE_HTTPS=true in environment to enable TLS
# WARNING: urlopen uses the system default SSL context. If your Splunk instance
# uses a self-signed certificate, connections will fail with SSLCertVerificationError.
# To fix: import ssl at the top of the file, then pass a custom context to urlopen:
#   ctx = ssl.create_default_context()
#   ctx.load_verify_locations("splunk-ca.pem")   # your CA cert
#   urlopen(req, context=ctx, timeout=10)
# For lab use only, you can disable verification (NEVER in production):
#   ctx.check_hostname = False
#   ctx.verify_mode = ssl.CERT_NONE
_use_https      = os.environ.get("SPLUNK_USE_HTTPS", "false").lower() == "true"
_protocol       = "https" if _use_https else "http"
HEC_URL         = f"{_protocol}://{SPLUNK_HOST}:{SPLUNK_PORT}/services/collector/event"

# Polling interval in seconds (5 minutes = 300)
POLL_INTERVAL = 300

# CSV data source (used in demo mode when no live API is available)
CSV_SOURCE = "security_events.csv"

# State file — tracks the last successfully ingested event timestamp
# so the script never sends duplicates across restarts
STATE_FILE = ".ingest_state.json"

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("ingest.log", encoding="utf-8"),
    ]
)
log = logging.getLogger(__name__)


# ── 2. State Management ───────────────────────────────────────────────────────

def load_state():
    """Load the last ingested timestamp and event hashes from state file."""
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"last_timestamp": None, "ingested_hashes": []}


def save_state(state):
    """Persist ingestion state to disk for crash recovery."""
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except IOError as e:
        log.error(f"Failed to save state: {e}")


def event_hash(event):
    """Return a short hash of an event to detect duplicates."""
    raw = json.dumps(event, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


# ── 3. Data Source — CSV (Demo) ───────────────────────────────────────────────

def load_events_from_csv(filepath, since_timestamp=None):
    """
    Load security events from a CSV file.
    Filters to events newer than since_timestamp if provided.

    Expected CSV columns (Kaggle Cyber Security Attacks dataset):
        Timestamp, Source IP Address, Destination IP Address,
        Attack Type, Severity Level, Anomaly Scores, Firewall Rules, Action Taken
    """
    if not os.path.exists(filepath):
        log.warning(f"CSV file '{filepath}' not found. Generating sample events.")
        return generate_sample_events(since_timestamp)

    events = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Kaggle uses 'Timestamp' (capital T) — preserve exact casing for state tracking
                # WARNING: ts <= since_timestamp is a string comparison, not a datetime comparison.
                # This is safe only if the CSV timestamps are in a lexicographically sortable
                # format such as ISO 8601 (YYYY-MM-DD HH:MM:SS). Formats like MM/DD/YYYY
                # will sort incorrectly and cause events to be skipped or re-ingested.
                ts = row.get("Timestamp", "")
                if since_timestamp and ts <= since_timestamp:
                    continue
                events.append({
                    "Timestamp":               ts,
                    "Source IP Address":       row.get("Source IP Address", ""),
                    "Destination IP Address":  row.get("Destination IP Address", ""),
                    "Attack Type":             row.get("Attack Type", "Unknown"),
                    "Severity Level":          row.get("Severity Level", "Low"),
                    "Anomaly Scores":          _safe_float(row.get("Anomaly Scores", "0")),
                    "Firewall Rules":          row.get("Firewall Rules", ""),
                    "Action Taken":            row.get("Action Taken", ""),
                })
    except Exception as e:
        log.error(f"Error reading CSV: {e}")

    return events


def _safe_float(value):
    """Convert a string to float safely — returns 0.0 on failure."""
    try:
        return float(value)
    except (ValueError, TypeError):
        return 0.0


def generate_sample_events(since_timestamp=None):
    """
    Generate 5 sample events for testing when no CSV is available.
    Field names (keys) match the Kaggle Cyber Security Attacks dataset exactly —
    so the SPL queries in queries.spl work against these sample events.

    Attack type values are restricted to those present in the real Kaggle dataset
    (DDoS, Intrusion, Malware) so demo output is consistent with the dashboard findings.

    Events are generated relative to since_timestamp (the last ingested timestamp),
    not the current wall-clock time. This ensures every run produces 5 genuinely new
    events regardless of how quickly the demo is re-run.

    If wall-clock offsets were used instead, each run's events would be anchored to
    'now minus a few minutes' — and if the previous run's max timestamp was also
    'now minus a few minutes', only 1 event (or none) would pass the ts > since_timestamp
    filter. Using since_timestamp as the base guarantees 5 new events every run.
    """
    attack_types = ["DDoS", "Intrusion", "Malware"]   # real Kaggle dataset values only
    severities   = ["Low", "Medium", "High"]   # real Kaggle dataset values only (no Critical)
    fw_rules     = ["Allow", "Block", "Deny", "Ignore"]

    # Base from last known timestamp, or 1 hour ago if first run
    if since_timestamp:
        try:
            base_time = datetime.fromisoformat(since_timestamp.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            base_time = datetime.now(timezone.utc) - timedelta(hours=1)
    else:
        base_time = datetime.now(timezone.utc) - timedelta(hours=1)

    sample = []
    for i in range(5):
        # Each event is 1 minute after the previous — all newer than base_time
        event_time = base_time + timedelta(minutes=(i + 1))
        sample.append({
            "Timestamp":               event_time.isoformat(),
            "Source IP Address":       f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
            "Destination IP Address":  f"10.0.0.{random.randint(1,50)}",
            "Attack Type":             random.choice(attack_types),
            "Severity Level":          random.choice(severities),
            "Anomaly Scores":          round(random.uniform(0, 100), 2),
            "Firewall Rules":          random.choice(fw_rules),
            "Action Taken":            random.choice(["Logged", "Blocked", "Ignored"]),
        })
    log.info("[*] Generated 5 sample events for demo.")
    return sample


# ── 4. Deduplication Filter ───────────────────────────────────────────────────

def filter_new_events(events, known_hashes):
    """
    Remove events already ingested in a previous run.

    Uses a set for O(1) hash lookups alongside an ordered list for correct
    truncation. A set alone is unordered — converting it back to a list and
    slicing with [-10000:] would remove random hashes, not the oldest ones,
    which could cause recently-seen events to be re-ingested as duplicates.

    Strategy:
      - seen_set    : set for fast O(1) lookup
      - ordered_list: list that preserves insertion order for safe truncation
    Keeps the list bounded to the last 10,000 entries (oldest removed first).
    """
    new_events     = []
    seen_set       = set(known_hashes)         # O(1) lookup
    ordered_list   = list(known_hashes)        # preserves chronological order

    for event in events:
        h = event_hash(event)
        if h not in seen_set:
            new_events.append(event)
            seen_set.add(h)
            ordered_list.append(h)             # append to end — oldest stay at front

    # Truncate from the front to remove the oldest hashes, not random ones
    if len(ordered_list) > 10000:
        ordered_list = ordered_list[-10000:]   # keeps the 10,000 most recent

    return new_events, ordered_list


# ── 5. Format for Splunk HEC ──────────────────────────────────────────────────

def format_for_hec(event):
    """
    Wrap a security event in the Splunk HEC JSON envelope.

    HEC expects:
        { "time": <epoch>, "index": "...", "sourcetype": "...", "event": {...} }
    """
    try:
        # Parse ISO timestamp to epoch — Splunk stores time as Unix epoch
        # Kaggle field is 'Timestamp' (capital T)
        ts_str = event.get("Timestamp", "")
        if ts_str:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            epoch = dt.timestamp()
        else:
            epoch = time.time()
    except (ValueError, TypeError):
        epoch = time.time()

    return {
        "time":       epoch,
        "index":      SPLUNK_INDEX,
        "sourcetype": "cyber_attack",
        "source":     "splunk_ingest.py",
        "event":      event,
    }


# ── 6. Send to Splunk HEC ─────────────────────────────────────────────────────

def send_to_hec(events):
    """
    Send a batch of events to Splunk via HTTP Event Collector (HEC).

    HEC accepts newline-delimited JSON — one JSON object per line.
    Returns (success_count, failure_count).
    """
    if not events:
        return 0, 0

    # Build the batch payload — newline-delimited JSON
    payload_lines = [json.dumps(format_for_hec(e)) for e in events]
    payload       = "\n".join(payload_lines).encode("utf-8")

    headers = {
        "Authorization": f"Splunk {SPLUNK_TOKEN}",
        "Content-Type":  "application/json",
    }

    try:
        req = Request(HEC_URL, data=payload, headers=headers, method="POST")
        with urlopen(req, timeout=10) as response:
            body = response.read().decode("utf-8")
            result = json.loads(body)
            if result.get("text") == "Success":
                log.info(f"[✔] Sent {len(events)} event(s) to Splunk.")
                return len(events), 0
            else:
                log.warning(f"[!] HEC responded: {result}")
                return 0, len(events)

    except HTTPError as e:
        log.error(f"[✘] HEC HTTP error {e.code}: {e.reason}")
        if e.code == 403:
            log.error("    → Check that your HEC token is correct and enabled.")
        elif e.code == 400:
            log.error("    → Malformed JSON payload — check event structure.")
        return 0, len(events)

    except URLError as e:
        log.error(f"[✘] Cannot reach Splunk at {HEC_URL}: {e.reason}")
        log.error("    → Is Splunk running? Is HEC enabled? (Settings → Data Inputs → HTTP Event Collector)")
        return 0, len(events)

    except Exception as e:
        log.error(f"[✘] Unexpected error sending to HEC: {e}")
        return 0, len(events)


# ── 7. Single Ingestion Cycle ─────────────────────────────────────────────────

def run_once(state):
    """
    Execute a single ingestion cycle:
    1. Load new events from source     (§3 load_events_from_csv)
    2. Deduplicate                     (§4 filter_new_events)
    3. Format and send to Splunk HEC   (§5 format_for_hec / §6 send_to_hec)
    4. Update and save state           (§2 save_state)
    """
    log.info("[*] Starting ingestion cycle...")

    # Load events newer than last run
    raw_events = load_events_from_csv(CSV_SOURCE, since_timestamp=state.get("last_timestamp"))

    if not raw_events:
        log.info("[*] No new events found.")
        return state

    # Deduplicate
    new_events, updated_hashes = filter_new_events(raw_events, state.get("ingested_hashes", []))

    if not new_events:
        log.info("[*] All events already ingested — no duplicates sent.")
        return state

    log.info(f"[*] {len(new_events)} new event(s) ready for ingestion.")

    # Send to Splunk
    ok, fail = send_to_hec(new_events)

    # Update state only on success
    if ok > 0:
        timestamps = [e.get("Timestamp", "") for e in new_events if e.get("Timestamp")]
        if timestamps:
            state["last_timestamp"] = max(timestamps)
        state["ingested_hashes"] = updated_hashes
        save_state(state)
        log.info(f"[✔] Cycle complete — {ok} sent, {fail} failed.")
    else:
        log.warning(f"[!] Cycle complete — 0 sent, {fail} failed. State not updated.")

    return state


# ── 8. Continuous Polling Loop ────────────────────────────────────────────────

def run_continuous():
    """
    Run the ingestion pipeline continuously, polling every POLL_INTERVAL seconds.
    Handles KeyboardInterrupt gracefully.
    """
    log.info("=" * 60)
    log.info("  Splunk Ingestion Pipeline — Continuous Mode")
    log.info(f"  Target : {HEC_URL}")
    log.info(f"  Index  : {SPLUNK_INDEX}")
    log.info(f"  Source : {CSV_SOURCE}")
    log.info(f"  Interval: every {POLL_INTERVAL}s")
    log.info("=" * 60)

    state = load_state()
    log.info(f"[*] Resuming from state: last_timestamp={state.get('last_timestamp', 'None')}")

    while True:
        try:
            state = run_once(state)
            log.info(f"[*] Sleeping {POLL_INTERVAL}s until next cycle...")
            time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:
            log.info("\n[!] Interrupted by user. Exiting cleanly.")
            break
        except Exception as e:
            log.error(f"[✘] Unhandled error in polling loop: {e}")
            log.info(f"[*] Retrying in {POLL_INTERVAL}s...")
            time.sleep(POLL_INTERVAL)


# ── 9. Entry Point ────────────────────────────────────────────────────────────

def main():
    log.info("=" * 60)
    log.info("  Splunk Ingestion Pipeline")
    log.info("  Author: Lucas Camargo")
    log.info("=" * 60)

    # Demo mode: run one cycle and exit (no continuous polling)
    log.info("[*] Running single ingestion cycle (demo mode)...")
    log.info("    To run continuously, pass --continuous flag.")

    state = load_state()
    state = run_once(state)

    log.info("[*] Demo cycle complete.")
    log.info("    Set SPLUNK_HEC_TOKEN env variable and update SPLUNK_HOST")
    log.info("    to connect to a real Splunk instance.")
    log.info("    To run continuous polling: python3 splunk_ingest.py --continuous")


if __name__ == "__main__":
    if "--continuous" in sys.argv:
        run_continuous()
    else:
        main()
