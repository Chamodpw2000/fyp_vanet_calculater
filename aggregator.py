#!/usr/bin/env python3
"""
VANET Aggregator  (merged with controller FF test harness)
==========================================================
Watches /tmp/ for vanet_raw_ready_N sentinel files.
Verifies all 321 per-node CSV files are present, aggregates
them, verifies blockchain-stored flow rules, then immediately
runs the forwarding-fraction anomaly detection in memory —
no intermediate JSON/CSV round-trip for the calculator inputs.

Output CSVs (per cycle) are written to /tmp/ai_agent/:
    aggregated_cycle_<N>.csv
    verified_flow_rules_cycle_<N>.csv
    verified_planned_inbound_cycle_<N>.csv
    controller_overhear_pool_summary_<N>.csv
    observed_forwarding_fractions_<N>.csv
    ff_node_anomaly_scores_<N>.csv
"""

import os
import csv
import glob
import json
import logging
import time
import sys
import hashlib
import requests

from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fabric_client_aggregator import get_record_by_cycle

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ─────────────────────────────────────────────
#  Paths
# ─────────────────────────────────────────────
WATCH_DIR      = "/tmp"
LOG_FILE       = "/tmp/vanet_aggregator.log"
AGGREGATED_DIR = "/tmp/ai_agent"          # ALL output files go here
DRL_DIR        = "/tmp/drl_agent"         # mirror copy for DRL agent
MIN_HOP_DIR    = "/tmp"                    # where NS-3 writes min_hops_next_hop_N.csv

# ─────────────────────────────────────────────
#  Constants  (mirrored from fix.cc)
# ─────────────────────────────────────────────
TOTAL_NODES      = 321
WAIT_TIMEOUT     = 0.5
N_VEHICLES       = 80       # node_id < 80 → VEHICLE, else RSU
FF_DEV_THRESHOLD = 0.5      # g_ff_deviation_threshold
FLOW_ID_OFFSET   = 1        # verified_flow_id = overhear_flow_id + 1

# ─────────────────────────────────────────────
#  Logging
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)


# ============================================================
#  HELPER
# ============================================================
def node_type(node_id: int) -> str:
    """VEHICLE / RSU split — same boundary the controller uses."""
    return "VEHICLE" if node_id < N_VEHICLES else "RSU"


# ============================================================
#  IPFS + FABRIC
# ============================================================
def fetch_from_ipfs(cid: str) -> str:
    response = requests.post(
        "http://127.0.0.1:5001/api/v0/cat",
        params={"arg": cid},
        timeout=30,
    )
    if response.status_code != 200:
        raise Exception(f"IPFS fetch failed: HTTP {response.status_code}")
    return response.text


def verify_cycle(cycle_id: int) -> dict:
    """
    Fabric → CID + stored_hash
    IPFS   → flow rules JSON + planned inbound JSON
    Recompute SHA-256 of combined payload → compare with stored_hash

    Returns a result dict (or None if no Fabric record found).
    """
    logger.info(f"Verifying cycle {cycle_id}...")

    record = get_record_by_cycle(cycle_id)
    if not record:
        logger.warning(f"Cycle {cycle_id}: not found on Fabric")
        return None

    cid_flow_rules      = record.get("cid_flow_rules", "")
    cid_planned_inbound = record.get("cid_planned_inbound", "")
    stored_hash         = record.get("sha256_hash", "")

    logger.info(
        f"Cycle {cycle_id}: cid_flow_rules={cid_flow_rules[:20]}... "
        f"cid_planned_inbound={cid_planned_inbound[:20]}... "
        f"hash={stored_hash[:16]}..."
    )

    flow_content    = fetch_from_ipfs(cid_flow_rules)
    inbound_content = fetch_from_ipfs(cid_planned_inbound)
    flow_data       = json.loads(flow_content)
    inbound_data    = json.loads(inbound_content)

    combined = {
        "flow_rules":      flow_data.get("flow_rules", []),
        "planned_inbound": inbound_data.get("planned_inbound", []),
    }

    canonical = json.dumps(
        combined, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    computed_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    verified = computed_hash == stored_hash
    logger.info(f"Cycle {cycle_id}: {'INTACT ✓' if verified else 'TAMPERED ✗'}")

    return {
        "cycle_id":           cycle_id,
        "cid_flow_rules":     cid_flow_rules,
        "cid_planned_inbound":cid_planned_inbound,
        "stored_hash":        stored_hash,
        "computed_hash":      computed_hash,
        "flow_rules":         combined["flow_rules"],
        "planned_inbound":    combined["planned_inbound"],
        "verified":           verified,
    }


# ============================================================
#  AGGREGATION  (per-node CSVs → merged rows in memory)
# ============================================================
def aggregate_node_csvs(cycle_id: int, present_nodes: list):
    """
    Reads all per-node overhear CSV files for this cycle.
    Writes the combined CSV to AGGREGATED_DIR.
    Also returns (header, all_rows) for in-memory use downstream.

    Returns (output_path, header, all_rows)  or  (None, None, [])
    """
    os.makedirs(AGGREGATED_DIR, exist_ok=True)

    all_rows = []
    header   = None

    for node_id in present_nodes:
        path = os.path.join(WATCH_DIR, f"vanet_node_data_{cycle_id}_{node_id}.csv")
        with open(path, "r", newline="") as f:
            reader = csv.reader(f)
            rows   = list(reader)

        if not rows:
            continue

        if header is None:
            header = rows[0]

        all_rows.extend(rows[1:])   # skip per-file header

    if header is None:
        logger.warning(f"[AGGREGATOR] Cycle {cycle_id} | no data in any per-node CSV")
        return None, None, []

    output_path = os.path.join(AGGREGATED_DIR, f"aggregated_cycle_{cycle_id}.csv")
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(all_rows)

    logger.info(
        f"[AGGREGATOR] Cycle {cycle_id} | "
        f"aggregated {len(all_rows)} rows from {len(present_nodes)} nodes "
        f"→ {output_path}"
    )

    # ── Mirror copy to DRL_DIR ────────────────────────────────────────────
    import shutil
    os.makedirs(DRL_DIR, exist_ok=True)
    drl_path = os.path.join(DRL_DIR, f"aggregated_cycle_{cycle_id}.csv")
    shutil.copy2(output_path, drl_path)
    logger.info(f"[AGGREGATOR] Cycle {cycle_id} | DRL mirror → {drl_path}")

    return output_path, header, all_rows


# ============================================================
#  CLEANUP
# ============================================================
def cleanup_node_csvs(cycle_id: int, present_nodes: list):
    deleted = 0
    for node_id in present_nodes:
        path = os.path.join(WATCH_DIR, f"vanet_node_data_{cycle_id}_{node_id}.csv")
        try:
            if os.path.exists(path):
                os.remove(path)
                deleted += 1
        except Exception as e:
            logger.warning(f"[AGGREGATOR] Could not remove {path}: {e}")

    sentinel_path = os.path.join(WATCH_DIR, f"vanet_raw_ready_{cycle_id}")
    try:
        if os.path.exists(sentinel_path):
            os.remove(sentinel_path)
    except Exception as e:
        logger.warning(f"[AGGREGATOR] Could not remove sentinel {sentinel_path}: {e}")

    logger.info(
        f"[AGGREGATOR] Cycle {cycle_id} | "
        f"cleaned up {deleted} per-node CSVs + sentinel"
    )


# ============================================================
#  SAVE VERIFIED CSVs  (unchanged from original aggregator)
# ============================================================
def save_verified_flow_rules_csv(cycle_id: int, flow_rules: list) -> str:
    os.makedirs(AGGREGATED_DIR, exist_ok=True)
    output_path = os.path.join(
        AGGREGATED_DIR, f"verified_flow_rules_cycle_{cycle_id}.csv"
    )
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "cycle", "timestamp", "flow_id", "src", "dst",
            "from_node", "to_node", "delta_value",
        ])
        for rule in flow_rules:
            writer.writerow([
                rule.get("cycle"),
                rule.get("timestamp"),
                rule.get("flow_id"),
                rule.get("src"),
                rule.get("dst"),
                rule.get("from_node"),
                rule.get("to_node"),
                rule.get("delta_value"),
            ])
    logger.info(
        f"[AGGREGATOR] Cycle {cycle_id} | "
        f"verified flow rules saved ({len(flow_rules)} rows) → {output_path}"
    )

    # ── Mirror copy to DRL_DIR ────────────────────────────────────────────
    os.makedirs(DRL_DIR, exist_ok=True)
    drl_path = os.path.join(DRL_DIR, f"verified_flow_rules_cycle_{cycle_id}.csv")
    with open(drl_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "cycle", "timestamp", "flow_id", "src", "dst",
            "from_node", "to_node", "delta_value",
        ])
        for rule in flow_rules:
            writer.writerow([
                rule.get("cycle"),
                rule.get("timestamp"),
                rule.get("flow_id"),
                rule.get("src"),
                rule.get("dst"),
                rule.get("from_node"),
                rule.get("to_node"),
                rule.get("delta_value"),
            ])
    logger.info(f"[AGGREGATOR] Cycle {cycle_id} | DRL mirror → {drl_path}")

    return output_path


def save_verified_planned_inbound_csv(cycle_id: int, planned_inbound: list) -> str:
    os.makedirs(AGGREGATED_DIR, exist_ok=True)
    output_path = os.path.join(
        AGGREGATED_DIR, f"verified_planned_inbound_cycle_{cycle_id}.csv"
    )
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "cycle", "flow_id", "node",
            "planned_inbound_by_subflow", "planned_inbound_by_mainflow",
        ])
        for entry in planned_inbound:
            writer.writerow([
                entry.get("cycle"),
                entry.get("flow_id"),
                entry.get("node"),
                entry.get("planned_inbound_by_subflow"),
                entry.get("planned_inbound_by_mainflow"),
            ])
    logger.info(
        f"[AGGREGATOR] Cycle {cycle_id} | "
        f"verified planned inbound saved ({len(planned_inbound)} rows) → {output_path}"
    )

    # ── Mirror copy to DRL_DIR ────────────────────────────────────────────
    os.makedirs(DRL_DIR, exist_ok=True)
    drl_path = os.path.join(DRL_DIR, f"verified_planned_inbound_cycle_{cycle_id}.csv")
    with open(drl_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "cycle", "flow_id", "node",
            "planned_inbound_by_subflow", "planned_inbound_by_mainflow",
        ])
        for entry in planned_inbound:
            writer.writerow([
                entry.get("cycle"),
                entry.get("flow_id"),
                entry.get("node"),
                entry.get("planned_inbound_by_subflow"),
                entry.get("planned_inbound_by_mainflow"),
            ])
    logger.info(f"[AGGREGATOR] Cycle {cycle_id} | DRL mirror → {drl_path}")

    return output_path


# ============================================================
#  LOAD SHORTEST-NEXT-HOP DATA  (from NS-3 min_hops_next_hop_N.csv)
#  Builds a lookup:  (flow_id, node_id) -> set of shortest next-hop ids
#  Rows with next_hop_node == 999 mean "all next hops equal / single
#  option" — indistinguishable, so those nodes are marked (via a
#  separate set) as NOT stretch-testable.
# ============================================================
def load_shortest_next_hops(cycle_id: int):
    path = os.path.join(MIN_HOP_DIR, f"min_hops_next_hop_{cycle_id}.csv")

    shortest = defaultdict(set)   # (fid, node) -> {shortest next hop ids}
    indistinct = set()            # (fid, node) with a 999 row (not testable)

    if not os.path.exists(path):
        logger.warning(
            f"[MIN-HOP] Cycle {cycle_id} | file not found: {path} "
            f"(is_stretched will be blank)"
        )
        return shortest, indistinct

    with open(path, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            fid  = int(row["flow_id"])
            node = int(row["node_id"])
            nh   = int(row["next_hop_node"])
            if nh == 999:
                indistinct.add((fid, node))
            else:
                shortest[(fid, node)].add(nh)

    logger.info(
        f"[MIN-HOP] Cycle {cycle_id} | loaded shortest next hops for "
        f"{len(shortest)} (flow,node) keys, {len(indistinct)} indistinct"
    )
    return shortest, indistinct


# ============================================================
#  STAGE 1 — load_cycle()
#  Builds in-memory structures from data already in memory.
#  No file I/O here — everything is passed in directly.
#
#  Parameters
#  ----------
#  overhear_rows  : list of lists  (data rows, NO header row)
#  overhear_header: list of str    (column names)
#  flow_rules     : list of dicts  (from IPFS / verify_cycle)
#  planned_inbound_list : list of dicts (from IPFS / verify_cycle)
#  cycle_id       : int
# ============================================================
def load_cycle(overhear_rows, overhear_header,
               flow_rules, planned_inbound_list,
               cycle_id: int) -> dict:

    # Map column name → index for the overhear pool rows
    col = {name: idx for idx, name in enumerate(overhear_header)}

    # ── 1a. Build overhear pool structures ───────────────────────────────
    inbound     = defaultdict(lambda: defaultdict(set))
    outbound    = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    watchers_in = defaultdict(lambda: defaultdict(set))
    watchers_out= defaultdict(lambda: defaultdict(set))
    all_watchers= set()
    sim_time    = None

    # ── Per-quarter binning (Fix A) ──────────────────────────────────────
    # A packet is binned by the quarter in which the NODE RECEIVED it
    # (the previous_tx_timestamp_s on the row where the node is the
    # intended_receiver — i.e. its upstream's tx time = arrival proxy).
    # Both inbound AND its forwarded copy are counted in that SAME quarter,
    # so a node that forwards everything shows 100% in every quarter → var 0.
    #
    # arrival_q[(fid, node)][pid] = quarter the node received pid
    arrival_q  = defaultdict(dict)
    inbound_q  = defaultdict(lambda: [set(), set(), set(), set()])
    outbound_q = defaultdict(lambda: [set(), set(), set(), set()])

    def _quarter(tx_str):
        try:
            tx_t = float(tx_str)
            q = int((tx_t % 1.0) / 0.25)
            return 3 if q > 3 else q
        except (KeyError, ValueError):
            return 0

    for row in overhear_rows:
        fid  = int(row[col["flow_id"]])
        wid  = int(row[col["watcher_node_id"]])
        pid  = int(row[col["packet_id"]])
        sndr = int(row[col["previous_sender_id"]])
        rcvr = int(row[col["intended_receiver_id"]])

        inbound[fid][rcvr].add(pid)
        watchers_in[fid][rcvr].add(wid)
        outbound[fid][sndr][rcvr].add(pid)
        watchers_out[fid][sndr].add(wid)
        all_watchers.add(wid)

        # This row means: sndr transmitted pid, rcvr is meant to receive it.
        # So pid ARRIVES at rcvr at this row's previous_tx_timestamp_s.
        q_arrival = _quarter(row[col["previous_tx_timestamp_s"]])
        arrival_q[(fid, rcvr)][pid] = q_arrival
        inbound_q[(fid, rcvr)][q_arrival].add(pid)

        st = float(row[col["sim_time_s"]])
        if sim_time is None or st > sim_time:
            sim_time = st

    # Second pass: bin each forwarded packet by the quarter its sender
    # RECEIVED it (look up arrival_q for that sender). Packets a node
    # forwards but was never seen receiving fall back to their own tx-quarter.
    for row in overhear_rows:
        fid  = int(row[col["flow_id"]])
        pid  = int(row[col["packet_id"]])
        sndr = int(row[col["previous_sender_id"]])

        sender_arrivals = arrival_q.get((fid, sndr), {})
        if pid in sender_arrivals:
            q_out = sender_arrivals[pid]          # same quarter it arrived
        else:
            q_out = _quarter(row[col["previous_tx_timestamp_s"]])
        outbound_q[(fid, sndr)][q_out].add(pid)

    # ── 1b. Build planned forwarding fractions from flow_rules list ──────
    # flow_rules dicts use flow_id with +1 offset (same as verified CSV)
    planned   = defaultdict(lambda: defaultdict(dict))
    flow_meta = {}

    for rule in flow_rules:
        v_fid = int(rule["flow_id"])
        fid   = v_fid - FLOW_ID_OFFSET          # back to overhear indexing
        src   = int(rule["src"])
        dst   = int(rule["dst"])
        frm   = int(rule["from_node"])
        to    = int(rule["to_node"])
        delta = float(rule["delta_value"])

        planned[fid][frm][to] = delta
        flow_meta[fid] = (src, dst)

    # ── 1c. Build planned inbound lookup from planned_inbound_list ───────
    # Same +1 offset applies here too
    planned_inbound = {}

    for entry in planned_inbound_list:
        fid  = int(entry["flow_id"]) - FLOW_ID_OFFSET
        node = int(entry["node"])
        planned_inbound[(fid, node)] = int(entry["planned_inbound_by_subflow"])

    return {
        "cycle_id":        cycle_id,
        "sim_time":        sim_time if sim_time is not None else 0.0,
        "inbound":         inbound,
        "outbound":        outbound,
        "watchers_in":     watchers_in,
        "watchers_out":    watchers_out,
        "all_watchers":    all_watchers,
        "planned":         planned,
        "flow_meta":       flow_meta,
        "planned_inbound": planned_inbound,
        "inbound_q":       inbound_q,
        "outbound_q":      outbound_q,
    }


# ============================================================
#  STAGE 2 — compute_cycle()
#  Faithful re-implementation of compute_observed_forwarding_fractions().
#  Zero changes to the calculation logic.
#  `writers` is a dict of three csv.writer objects (headers already written).
# ============================================================
def compute_cycle(data: dict, writers: dict,
                  shortest_next_hops: dict, indistinct_nodes: set) -> dict:
    cycle    = data["cycle_id"]
    sim_time = data["sim_time"]
    inbound  = data["inbound"]
    outbound = data["outbound"]
    watchers_in  = data["watchers_in"]
    watchers_out = data["watchers_out"]
    planned      = data["planned"]
    flow_meta    = data["flow_meta"]
    planned_inbound = data["planned_inbound"]
    inbound_q    = data["inbound_q"]
    outbound_q   = data["outbound_q"]

    pool_w  = writers["pool"]
    ff_w    = writers["ff"]
    score_w = writers["score"]

    total_computed = 0
    no_cov         = 0
    detected_total = 0

    all_flow_ids = set(inbound.keys()) | set(outbound.keys())

    for fid in sorted(all_flow_ids):

        flow_src, flow_dst = flow_meta.get(fid, (-1, -1))
        flow_node_records  = []
        flow_node_ids = (
            set(inbound.get(fid, {}).keys())
            | set(outbound.get(fid, {}).keys())
        )
        for node_id in sorted(flow_node_ids):
            nexthop_map = outbound.get(fid, {}).get(node_id, {})

            if node_id == flow_src or node_id == flow_dst:
                role = "SOURCE" if node_id == flow_src else "DESTINATION"
                pool_w.writerow([
                    cycle, sim_time, fid, flow_src, flow_dst,
                    node_id, role, -1, 0, 0, 0, 0,
                ])
                continue

            ntype            = node_type(node_id)
            unique_inbound   = len(inbound[fid].get(node_id, set()))
            num_watchers_in  = len(watchers_in[fid].get(node_id, set()))

            if unique_inbound == 0:
                no_cov += 1

            total_outbound_from_node = sum(
                len(pset) for pset in nexthop_map.values()
            )

            received_but_not_forwarded = (
            unique_inbound > 0 and total_outbound_from_node == 0
            )


            pool_w.writerow([
                cycle, sim_time, fid, flow_src, flow_dst,
                node_id, "INTERMEDIATE", -1,
                unique_inbound, 0, num_watchers_in, 0,
            ])

            node_sum_abs_dev  = 0.0
            node_num_next_hops = 0

            for next_hop in sorted(nexthop_map.keys()):
                unique_outbound  = len(nexthop_map[next_hop])
                num_watchers_out = len(watchers_out[fid].get(node_id, set()))
                expected_delta   = (
                    planned.get(fid, {}).get(node_id, {}).get(next_hop, 0.0)
                )

                observed_ff = 0.0
                deviation   = 0.0
                if unique_inbound > 0:
                    observed_ff = unique_outbound / unique_inbound
                    deviation   = observed_ff - expected_delta
                    total_computed     += 1
                    node_sum_abs_dev   += abs(deviation)
                    node_num_next_hops += 1

                pool_w.writerow([
                    cycle, sim_time, fid, flow_src, flow_dst,
                    node_id, "INTERMEDIATE", next_hop,
                    unique_inbound, unique_outbound,
                    num_watchers_in, num_watchers_out,
                ])

                ff_w.writerow([
                    cycle, sim_time, fid, flow_src, flow_dst,
                    node_id, ntype, next_hop, node_type(next_hop),
                    unique_inbound, unique_outbound,
                    f"{observed_ff:.4f}", f"{expected_delta:.4f}",
                    f"{deviation:.4f}",
                ])
            # A node that received packets but forwarded none has a complete
            # forwarding failure, so assign the maximum deviation value.
            if received_but_not_forwarded:
                node_sum_abs_dev = 1.0
            # Score every intermediate node that received at least one packet,
            # even when it never appeared as a previous_sender_id.
            # Only score if planned inbound is known and > 0.
            pi_subflow = planned_inbound.get((fid, node_id), 0)
            if unique_inbound > 0 and pi_subflow > 0:
                detected = (
                    1
                    if node_num_next_hops > 0
                    and node_sum_abs_dev > FF_DEV_THRESHOLD
                    else 0
                )
                detected_total += detected

                node_pdr = (
                    total_outbound_from_node / unique_inbound
                ) * 100.0

                # ── FLOW-STRETCH CHECK ────────────────────────────────────
                # Did this node forward ANY packet to one of its shortest
                # next hops? If it sent nothing to the shortest path(s),
                # it is stretching. 999 rows are indistinguishable → blank.
                key = (fid, node_id)
                if key in indistinct_nodes:
                    is_stretched = ""          # not testable (all hops equal)
                elif key in shortest_next_hops:
                    shortest_set   = shortest_next_hops[key]
                    forwarded_to   = set(nexthop_map.keys())   # who node sent to
                    sent_to_short  = forwarded_to & shortest_set
                    is_stretched   = len(sent_to_short) == 0   # True = stretched
                else:
                    is_stretched = ""          # no min-hop info for this node

                # ── PER-QUARTER PDR VARIANCE ──────────────────────────────
                # Split the second into 4 parts (0.25 each). For each part:
                #   pdr_q = outbound_q / inbound_q * 100
                # If no packets arrived in that part, pdr_q = 100 (not malicious).
                in_q  = inbound_q.get((fid, node_id),  [set(), set(), set(), set()])
                out_q = outbound_q.get((fid, node_id), [set(), set(), set(), set()])
                pdr_quarters = []
                for qi in range(4):
                    n_in  = len(in_q[qi])
                    n_out = len(out_q[qi])
                    if n_in == 0:
                        pdr_quarters.append(100.0)     # no inbound → treat as healthy
                    else:
                        pdr_quarters.append((n_out / n_in) * 100.0)

                mean_q = sum(pdr_quarters) / 4.0
                pdr_var = sum((p - mean_q) ** 2 for p in pdr_quarters) / 4.0

                flow_node_records.append({
                    "node_id":        node_id,
                    "ntype":          ntype,
                    "n_next_hops":    node_num_next_hops,
                    "sum_abs_dev":    node_sum_abs_dev,
                    "detected":       detected,
                    "unique_inbound": unique_inbound,
                    "total_outbound": total_outbound_from_node,
                    "node_pdr":       node_pdr,
                    "pi_subflow":     pi_subflow,
                    "is_stretched":   is_stretched,
                    "pdr_var":        pdr_var,
                })

        # ── Pass 2: mean PDR across this flow's scored nodes ─────────────
        if flow_node_records:
            mean_pdr_flow = (
                sum(r["node_pdr"] for r in flow_node_records)
                / len(flow_node_records)
            )
        else:
            mean_pdr_flow = 0.0

        for r in flow_node_records:
            pdr_deviation = mean_pdr_flow - r["node_pdr"]

            normalized_abs_dev = (
                r["sum_abs_dev"] / r["n_next_hops"]
                if r["n_next_hops"] > 0 
                else 1.0
            )

            inbound_ratio = (
                r["pi_subflow"] / r["unique_inbound"]
                if r["unique_inbound"] > 0 else 0.0
            )

            score_w.writerow([
                cycle, sim_time, fid, flow_src, flow_dst,
                r["node_id"], r["ntype"], r["n_next_hops"],
                f"{r['sum_abs_dev']:.4f}",
                f"{normalized_abs_dev:.4f}",
                        f"{FF_DEV_THRESHOLD:.4f}",
                        r["detected"], r["unique_inbound"], r["total_outbound"],
                        f"{r['node_pdr']:.2f}", f"{mean_pdr_flow:.2f}",
                        f"{pdr_deviation:.2f}", f"{inbound_ratio:.4f}",
                        r["is_stretched"], f"{r['pdr_var']:.4f}",
                    ])

    return {
        "total_computed": total_computed,
        "no_cov":         no_cov,
        "detected_total": detected_total,
        "watchers":       len(data["all_watchers"]),
    }


# ============================================================
#  WRITE RESULT CSVs  (pool / ff / score)
#  Opens the three output files, writes headers, calls
#  load_cycle() then compute_cycle(), then closes.
# ============================================================
def run_ff_analysis(cycle_id: int,
                    overhear_rows, overhear_header,
                    flow_rules, planned_inbound_list):
    """
    Glue between the aggregator and the FF calculator.
    All inputs are already in memory — no file reads inside.
    Writes the three result CSVs to AGGREGATED_DIR.
    """
    os.makedirs(AGGREGATED_DIR, exist_ok=True)

    pool_path  = os.path.join(
        AGGREGATED_DIR, f"controller_overhear_pool_summary_{cycle_id}.csv")
    ff_path    = os.path.join(
        AGGREGATED_DIR, f"observed_forwarding_fractions_{cycle_id}.csv")
    score_path = os.path.join(
        AGGREGATED_DIR, f"ff_node_anomaly_scores_{cycle_id}.csv")

    with open(pool_path, "w", newline="") as pf, \
         open(ff_path,   "w", newline="") as ff, \
         open(score_path,"w", newline="") as sf:

        pool_w  = csv.writer(pf)
        ff_w    = csv.writer(ff)
        score_w = csv.writer(sf)

        # ── headers ──────────────────────────────────────────────────────
        pool_w.writerow([
            "cycle_id", "sim_time_s", "flow_id", "flow_source",
            "flow_destination", "node_id", "node_role", "next_hop_id",
            "unique_inbound_count", "unique_outbound_count",
            "num_watchers_inbound", "num_watchers_outbound",
        ])
        ff_w.writerow([
            "cycle_id", "sim_time_s", "flow_id", "flow_source",
            "flow_destination", "forwarding_node_id",
            "forwarding_node_type", "next_hop_id", "next_hop_type",
            "unique_inbound_count", "unique_outbound_to_next_hop",
            "observed_ff", "expected_ff_planned", "ff_deviation",
        ])
        score_w.writerow([
            "cycle_id", "sim_time_s", "flow_id", "flow_source",
            "flow_destination", "node_id", "node_type",
            "num_active_next_hops", "sum_abs_ff_deviation",
            "sum_abs_ff_deviation_normalized",
            "threshold", "detected", "total_inbound",
            "total_outbound", "node_pdr", "mean_pdr_flow",
            "pdr_deviation", "inbound_ratio", "is_stretched", "pdr_var",
        ])

        writers = {"pool": pool_w, "ff": ff_w, "score": score_w}

        # ── Stage 1 : build in-memory data structures ─────────────────
        data = load_cycle(
            overhear_rows, overhear_header,
            flow_rules, planned_inbound_list,
            cycle_id,
        )

        # ── Stage 1b : load shortest next hops from NS-3 min-hop file ──
        shortest_next_hops, indistinct_nodes = load_shortest_next_hops(cycle_id)

        # ── Stage 2 : run FF / deviation / PDR / anomaly math ─────────
        stats = compute_cycle(data, writers, shortest_next_hops, indistinct_nodes)

    # ── Mirror the three FF CSVs to DRL_DIR ──────────────────────────────
    import shutil
    os.makedirs(DRL_DIR, exist_ok=True)
    for src_path in [pool_path, ff_path, score_path]:
        dst_path = os.path.join(DRL_DIR, os.path.basename(src_path))
        shutil.copy2(src_path, dst_path)
        logger.info(f"[FF-ANALYSIS] Cycle {cycle_id} | DRL mirror → {dst_path}")

    logger.info(
        f"[FF-ANALYSIS] Cycle {cycle_id} | t={data['sim_time']}s | "
        f"FF computed={stats['total_computed']} | "
        f"nodes detected={stats['detected_total']} | "
        f"zero-inbound nodes={stats['no_cov']} | "
        f"watchers={stats['watchers']}"
    )
    logger.info(
        f"[FF-ANALYSIS] Cycle {cycle_id} | "
        f"→ {os.path.basename(pool_path)}, "
        f"{os.path.basename(ff_path)}, "
        f"{os.path.basename(score_path)}"
    )
    return stats



# ============================================================
#  ATTACK-DETECTION SENTINEL
#  Signals detector.py that ff_node_anomaly_scores_N.csv is
#  fully written and ready to be read.
# ============================================================
def write_attack_sentinel(cycle_id: int) -> str:
    sentinel_path = os.path.join(
        AGGREGATED_DIR, f"vanet_attack_ready_{cycle_id}"
    )
    with open(sentinel_path, "w") as f:
        pass
    logger.info(
        f"[AGGREGATOR] Cycle {cycle_id} | "
        f"attack-detection sentinel written → {sentinel_path}"
    )
    return sentinel_path

# ============================================================
#  DRL-AGENT SENTINEL
#  Signals the DRL agent that all mirrored files for cycle N
#  are fully written and ready to be read.
# ============================================================
def write_drl_sentinel(cycle_id: int) -> str:
    os.makedirs(DRL_DIR, exist_ok=True)
    sentinel_path = os.path.join(
        DRL_DIR, f"drl_cycle_{cycle_id}_ready_mid"
    )
    with open(sentinel_path, "w") as f:
        pass
    logger.info(
        f"[AGGREGATOR] Cycle {cycle_id} | "
        f"DRL sentinel written → {sentinel_path}"
    )
    return sentinel_path


# ============================================================
#  PROCESS CYCLE  (main per-cycle orchestrator)
# ============================================================
def process_cycle(cycle_id: int):
    logger.info("=" * 55)
    logger.info(f"[AGGREGATOR] Sentinel detected — cycle {cycle_id}")

    time.sleep(WAIT_TIMEOUT)

    # ── Step 1: Check all per-node overhear CSV files ────────────────────
    present = []
    missing = []

    for node_id in range(TOTAL_NODES):
        path = os.path.join(
            WATCH_DIR, f"vanet_node_data_{cycle_id}_{node_id}.csv"
        )
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

    # ── Step 2: Verify blockchain-stored flow rules ───────────────────────
    result = verify_cycle(cycle_id)

    if result is None:
        logger.warning(
            f"[AGGREGATOR] Cycle {cycle_id} | "
            f"Skipping — no Fabric record found"
        )
        return

    if not result["verified"]:
        logger.warning(
            f"[AGGREGATOR] Cycle {cycle_id} | "
            f"Blockchain verification FAILED ✗ — possible tampering"
        )
        return

    logger.info(
        f"[AGGREGATOR] Cycle {cycle_id} | "
        f"Blockchain verification PASSED ✓ | "
        f"flow_rules={len(result['flow_rules'])}"
    )

    # ── Step 3: Save verified flow rules CSV ─────────────────────────────
    save_verified_flow_rules_csv(cycle_id, result["flow_rules"])

    # ── Step 4: Aggregate per-node CSVs → file + in-memory rows ──────────
    aggregated_path, overhear_header, overhear_rows = aggregate_node_csvs(
        cycle_id, present
    )

    # ── Step 5: Save verified planned inbound CSV ─────────────────────────
    save_verified_planned_inbound_csv(cycle_id, result["planned_inbound"])

    # ── Step 6: Cleanup per-node CSVs + sentinel ──────────────────────────
    if aggregated_path:
        cleanup_node_csvs(cycle_id, present)

    # ── Step 7: Run FF anomaly analysis entirely in memory ────────────────
    if overhear_header is None or not overhear_rows:
        logger.warning(
            f"[AGGREGATOR] Cycle {cycle_id} | "
            f"No overhear rows — skipping FF analysis"
        )
        return

    run_ff_analysis(
        cycle_id,
        overhear_rows,
        overhear_header,
        result["flow_rules"],        # list of dicts — direct from IPFS
        result["planned_inbound"],   # list of dicts — direct from IPFS
    )

    write_attack_sentinel(cycle_id)
    write_drl_sentinel(cycle_id)

# ============================================================
#  WATCHDOG EVENT HANDLER
# ============================================================
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
            logger.warning(
                f"[AGGREGATOR] Could not parse cycle id from: {filename}"
            )
            return

        process_cycle(cycle_id)


# ============================================================
#  ENTRY POINT
# ============================================================
def main():
    os.makedirs(AGGREGATED_DIR, exist_ok=True)
    logger.info("[AGGREGATOR] Starting — watching /tmp/ for vanet_raw_ready_N ...")

    # Handle sentinels that arrived before this process started
    for sentinel in sorted(
        glob.glob(os.path.join(WATCH_DIR, "vanet_raw_ready_*"))
    ):
        try:
            cycle_id = int(
                os.path.basename(sentinel).replace("vanet_raw_ready_", "")
            )
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
