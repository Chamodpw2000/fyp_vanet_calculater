import os

# ─── Paths ───────────────────────────────────────────────
BASE_DIR        = os.path.expanduser("~/vanet_middleware")
LOG_FILE        = os.path.join(BASE_DIR, "logs/middleware.log")

# Directory that fix.cc writes trigger files to
WATCH_DIR       = "/tmp"

# ─── IPFS ────────────────────────────────────────────────
IPFS_API_ADD    = "http://127.0.0.1:5001/api/v0/add"
IPFS_API_PIN    = "http://127.0.0.1:5001/api/v0/pin/add"
IPFS_RETRIES    = 3

# ─── Fabric Paths ────────────────────────────────────────
FABRIC_BASE     = os.path.expanduser("~/fabric/fabric-samples")
TEST_NETWORK    = os.path.join(FABRIC_BASE, "test-network")
BIN_DIR         = os.path.join(FABRIC_BASE, "bin")
CFG_DIR         = os.path.join(FABRIC_BASE, "config")

ORG1_BASE       = os.path.join(TEST_NETWORK,
                  "organizations/peerOrganizations/org1.example.com")

TLS_CERT_ORG1   = os.path.join(ORG1_BASE,
                  "peers/peer0.org1.example.com/tls/ca.crt")

MSP_PATH_ORG1   = os.path.join(ORG1_BASE,
                  "users/Admin@org1.example.com/msp")

TLS_CERT_ORG2   = os.path.join(TEST_NETWORK,
                  "organizations/peerOrganizations/org2.example.com"
                  "/peers/peer0.org2.example.com/tls/ca.crt")

ORDERER_CA      = os.path.join(TEST_NETWORK,
                  "organizations/ordererOrganizations/example.com"
                  "/orderers/orderer.example.com/msp/tlscacerts"
                  "/tlsca.example.com-cert.pem")

# ─── Fabric Network ──────────────────────────────────────
CHANNEL_NAME    = "mychannel"
CHAINCODE_NAME  = "flowrecord"
PEER_ORG1       = "localhost:7051"
PEER_ORG2       = "localhost:9051"
ORDERER         = "localhost:7050"
