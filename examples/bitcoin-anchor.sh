#!/usr/bin/env bash
# Anchor an accumulator to Bitcoin with OpenTimestamps, then check the anchor
# with veracity. For interoperating with OpenTimestamps and anchoring services
# such as Markovian Protocol's.
#
# Stamping needs the stock OpenTimestamps client (pip install opentimestamps-client).
# Checking does not: veracity parses the proof itself and talks to nothing.
set -euo pipefail

PEAKS=${1:-peaks.hex}   # one peak hash per line, hex, accumulator order

# 1. The digest: sha256 over the peaks concatenated in accumulator order.
DIGEST=$(veracity accumulator-ots-hash --peaks "$PEAKS" | awk '/accumulator digest/ {print $3}')
echo "accumulator digest: $DIGEST"

# 2. Stamp the concatenated peaks, not the digest. `ots stamp` hashes the file
#    it is given, so the proof commits to sha256(payload), which is the digest.
grep -v '^[[:space:]]*#' "$PEAKS" | tr -d '[:space:]' | xxd -r -p > accumulator.payload
test "$(shasum -a 256 accumulator.payload | cut -d' ' -f1)" = "$DIGEST"
ots stamp accumulator.payload

# 3. Wait for a Bitcoin block, then complete the proof from the calendars.
#    (ots upgrade is a no-op until the block is mined; rerun it.)
ots upgrade accumulator.payload.ots

# 4. Check it. veracity verifies in process that the proof commits to this exact
#    digest, and prints the block and the Merkle root that block must have.
veracity accumulator-ots-hash --peaks "$PEAKS" --ots accumulator.payload.ots

# 5. The last step is yours: compare that Merkle root with the block header you
#    trust. Any node or explorer will tell you block N's Merkle root.
