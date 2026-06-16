import subprocess
import os
import json
import logging
from config import (
    BIN_DIR, CFG_DIR, CHANNEL_NAME,
    PEER_ORG1, PEER_ORG2, ORDERER,
    TLS_CERT_ORG1, TLS_CERT_ORG2,
    MSP_PATH_ORG1, ORDERER_CA
)

logger = logging.getLogger(__name__)


def _get_fabric_env() -> dict:
    env = os.environ.copy()
    env.update({
        "PATH":                        f"{BIN_DIR}:{env.get('PATH', '')}",
        "FABRIC_CFG_PATH":             CFG_DIR,
        "CORE_PEER_TLS_ENABLED":       "true",
        "CORE_PEER_LOCALMSPID":        "Org1MSP",
        "CORE_PEER_ADDRESS":           PEER_ORG1,
        "CORE_PEER_TLS_ROOTCERT_FILE": TLS_CERT_ORG1,
        "CORE_PEER_MSPCONFIGPATH":     MSP_PATH_ORG1,
    })
    return env


def get_record_by_cycle(cycle_id: int) -> dict:
    """
    Queries Fabric ledger using cycle_id.
    Returns dict with cid and sha256_hash.
    Returns None if not found.
    """
    args_json = (
        f'{{"function":"GetRecordsByCycle",'
        f'"Args":["{cycle_id}"]}}'
    )

    cmd = [
        "peer", "chaincode", "query",
        "-C", CHANNEL_NAME,
        "-n", "flowrecord",
        "-c", args_json
    ]

    try:
        result = subprocess.run(
            cmd,
            env=_get_fabric_env(),
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode == 0:
            records = json.loads(result.stdout.strip())
            if records and len(records) > 0:
                return records[0]
            logger.warning(f"No record found for cycle {cycle_id}")
            return None
        else:
            logger.error(f"Fabric query failed: {result.stderr}")
            return None

    except Exception as e:
        logger.error(f"get_record_by_cycle error: {e}")
        return None


