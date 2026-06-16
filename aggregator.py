#!/usr/bin/env python3
"""
VANET Aggregator
Watches /tmp/ for vanet_raw_ready_N sentinel files.
Verifies all 100 per-node CSV files are present, then logs ready.
"""

import os
import glob
import logging
import time
import sys
import hashlib
import json
import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fabric_client_aggregator import get_record_by_cycle

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WATCH_DIR   = "/tmp"
LOG_FILE    = "/tmp/vanet_aggregator.log"
TOTAL_NODES = 100
WAIT_TIMEOUT = 0.5

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def fetch_from_ipfs(cid: str) -> str:
    """
    Fetches content from IPFS by CID.
    Returns raw content string.
    """
    response = requests.post(
        "http://127.0.0.1:5001/api/v0/cat",
        params={"arg": cid},
        timeout=30
    )
    if response.status_code != 200:
        raise Exception(f"IPFS fetch failed: HTTP {response.status_code}")
    return response.text

def verify_cycle(cycle_id: int) -> dict:
    """
    Full verification pipeline for one cycle:

    cycle_id
        ↓
    Fabric → get CID + stored_hash
        ↓
    IPFS → get flow rules JSON
        ↓
    recompute SHA-256
        ↓
    compare with stored_hash

    Returns:
    {
        "cycle_id":       N,
        "cid":            "Qm...",
        "stored_hash":    "...",
        "computed_hash":  "...",
        "flow_rules":     [...],
        "verified":       True/False
    }
    """
    logger.info(f"Verifying cycle {cycle_id}...")

    # Step 1: cycle_id → Fabric → CID + stored_hash
    record = get_record_by_cycle(cycle_id)
    if not record:
        logger.warning(f"Cycle {cycle_id}: not found on Fabric")
        return None

    cid         = record.get("cid", "")
    stored_hash = record.get("sha256_hash", "")

    logger.info(f"Cycle {cycle_id}: CID={cid[:20]}... "
                f"hash={stored_hash[:16]}...")

    # Step 2: CID → IPFS → flow rules JSON
    content   = fetch_from_ipfs(cid)
    flow_data = json.loads(content)

    # Step 3: recompute hash from fetched content
    canonical = json.dumps(
        flow_data,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=True
    )
    computed_hash = hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()

    # Step 4: compare
    verified = (computed_hash == stored_hash)

    status = "INTACT ✓" if verified else "TAMPERED ✗"
    logger.info(f"Cycle {cycle_id}: {status}")

    return {
        "cycle_id":      cycle_id,
        "cid":           cid,
        "stored_hash":   stored_hash,
        "computed_hash": computed_hash,
        "flow_rules":    flow_data.get("flow_rules", []),
        "verified":      verified
    }

def process_cycle(cycle_id: int):

    logger.info(f"{'='*55}")
    logger.info(f"[AGGREGATOR] Sentinel detected — cycle {cycle_id}")

    time.sleep(WAIT_TIMEOUT)

    # ── Step 1: Check all per-node overhear CSV files are present ───────────
    present = []
    missing = []

    for node_id in range(TOTAL_NODES):
        path = os.path.join(WATCH_DIR, f"vanet_node_data_{cycle_id}_{node_id}.csv")
        if os.path.exists(path):
            present.append(node_id)
        else:
            missing.append(node_id)

    if missing:
        logger.warning(
            f"[AGGREGATOR] Cycle {cycle_id} | "
            f"Only {len(present)}/{TOTAL_NODES} files present | "
            f"Missing nodes: {missing}"
        )
    else:
        logger.info(
            f"[AGGREGATOR] Cycle {cycle_id} | "
            f"All {TOTAL_NODES} node files ready ✓"
        )

    # ── Step 2: Verify blockchain-stored flow rules for this cycle ──────────
    result = verify_cycle(cycle_id)

    if result is None:
        logger.warning(
            f"[AGGREGATOR] Cycle {cycle_id} | "
            f"Skipping verification — no Fabric record found"
        )
        return

    if result["verified"]:
        logger.info(
            f"[AGGREGATOR] Cycle {cycle_id} | "
            f"Blockchain verification PASSED ✓ | "
            f"flow_rules={len(result['flow_rules'])}"
        )
    else:
        logger.warning(
            f"[AGGREGATOR] Cycle {cycle_id} | "
            f"Blockchain verification FAILED ✗ — possible tampering"
        )


class RawReadyEventHandler(FileSystemEventHandler):

    def on_created(self, event):
        if event.is_directory:
            return

        filename = os.path.basename(event.src_path)

        if not filename.startswith("vanet_raw_ready_"):
            return

        try:
            cycle_id = int(filename.replace("vanet_raw_ready_", ""))
        except ValueError:
            logger.warning(f"[AGGREGATOR] Could not parse cycle id from: {filename}")
            return

        process_cycle(cycle_id)


def main():
    logger.info("[AGGREGATOR] Starting — watching /tmp/ for vanet_raw_ready_N ...")

    # Handle missed sentinels at startup
    for sentinel in sorted(glob.glob(os.path.join(WATCH_DIR, "vanet_raw_ready_*"))):
        try:
            cycle_id = int(os.path.basename(sentinel).replace("vanet_raw_ready_", ""))
            process_cycle(cycle_id)
        except ValueError:
            pass

    observer = Observer()
    observer.schedule(RawReadyEventHandler(), WATCH_DIR, recursive=False)
    observer.start()

    logger.info("[AGGREGATOR] Ready — waiting for NS-3 sentinels...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()
    logger.info("[AGGREGATOR] Stopped.")


if __name__ == "__main__":
    main()