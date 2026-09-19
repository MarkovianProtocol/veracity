#!/usr/bin/env bash
# Anchor an accumulator to Bitcoin, then check the anchor with veracity.
#
# Stamping needs the stock OpenTimestamps client (pip install opentimestamps-client).
# Checking does not: veracity parses the proof itself and talks to nothing.
set -euo pipefail

PEAKS=${1:-peaks.hex}   # one peak hash per line, hex, accumulator order

# 1. The root the checkpoint receipt signs: sha256 over the peaks concatenated.
ROOT=$(veracity accumulator-root --peaks "$PEAKS" | awk '/accumulator root/ {print $3}')
echo "accumulator root: $ROOT"

# 2. Stamp it. The calendars return a proof that is pending until a block closes.
printf '%s' "$ROOT" | xxd -r -p > accumulator.root
ots stamp accumulator.root

# 3. Wait for a Bitcoin block, then complete the proof from the calendars.
#    (ots upgrade is a no-op until the block is mined; rerun it.)
ots upgrade accumulator.root.ots

# 4. Check it. veracity verifies in process that the proof commits to this exact
#    root, and prints the block and the Merkle root that block must have.
veracity accumulator-root --peaks "$PEAKS" --ots accumulator.root.ots

# 5. The last step is yours: compare that Merkle root with the block header you
#    trust. Any node or explorer will tell you block N's Merkle root.
