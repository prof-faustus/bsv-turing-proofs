#!/bin/sh
# Start the pinned BSV node (bitcoin-sv 1.2.3) on regtest with Genesis and Chronicle active
# from block 1 and main-net standardness enforced at mempool acceptance (acceptnonstdtxn=0).
# Data lives in ./node-data; RPC on 127.0.0.1:18432 (prover/prover).
set -e
mkdir -p node-data
cp bitcoin.conf node-data/bitcoin.conf
docker rm -f bsv-turing-proofs-node >/dev/null 2>&1 || true
docker run --platform linux/amd64 --name bsv-turing-proofs-node -p 18432:18432 \
  -v "$(pwd)/node-data:/data" -d \
  bitcoinsv/bitcoin-sv@sha256:d96fe4786a00e5fc10bc9e0e76a6006376f9472d4eb74d07e4c1e0d019493d33 \
  bitcoind -conf=/data/bitcoin.conf -datadir=/data -printtoconsole
i=0
until docker exec bsv-turing-proofs-node bitcoin-cli -conf=/data/bitcoin.conf -datadir=/data getblockcount >/dev/null 2>&1; do
  i=$((i+1)); [ $i -gt 60 ] && { echo "node did not start"; exit 1; }; sleep 1
done
echo "node ready"
