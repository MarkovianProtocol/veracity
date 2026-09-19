package veracity

import (
	"bufio"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The MMR(39) accumulator from the MMRIVER draft KAT: the peaks at mmr index 38,
// which are nodes 30, 37 and 38 (1-based 31, 38, 39).
var kat39Peaks = []string{
	"d4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7",
	"6a169105dcc487dbbae5747a0fd9b1d33a40320cf91cf9a323579139e7ff72aa",
	"e9a5f5201eb3c3c856e0a224527af5ac7eb1767fb1aff9bd53ba41a60cde9785",
}

// The root is sha256 over the three peaks concatenated, nothing else. Recomputed
// by hand from the KAT hashes above: 0a3f00d3...
const kat39Root = "0a3f00d3ffdbf0d2d8900814e5463931b951231289e2f9be38c0ad1fc9a99d2c"

func peaksFromHex(t *testing.T, in []string) [][]byte {
	t.Helper()
	out := make([][]byte, 0, len(in))
	for _, s := range in {
		b, err := hex.DecodeString(s)
		require.NoError(t, err)
		out = append(out, b)
	}
	return out
}

// TestAccumulatorRootKAT39 pins the root to the draft's own MMR(39) vector.
func TestAccumulatorRootKAT39(t *testing.T) {
	root := accumulatorRoot(peaksFromHex(t, kat39Peaks))
	assert.Equal(t, kat39Root, hex.EncodeToString(root[:]))
}

// TestAccumulatorRootOrderMatters shows the root is over the peaks in accumulator
// order: reordering them is a different log state and must not produce the same root.
func TestAccumulatorRootOrderMatters(t *testing.T) {
	peaks := peaksFromHex(t, kat39Peaks)
	swapped := [][]byte{peaks[1], peaks[0], peaks[2]}
	assert.NotEqual(t, accumulatorRoot(peaks), accumulatorRoot(swapped))
}

func TestParsePeaksHex(t *testing.T) {
	in := "# the MMR(39) accumulator\n" + strings.Join(kat39Peaks, "\n") + "\n\n"
	peaks, err := parsePeaksHex(bufio.NewScanner(strings.NewReader(in)))
	require.NoError(t, err)
	require.Len(t, peaks, 3)
	root := accumulatorRoot(peaks)
	assert.Equal(t, kat39Root, hex.EncodeToString(root[:]))
}

func TestParsePeaksHexRejectsGarbage(t *testing.T) {
	_, err := parsePeaksHex(bufio.NewScanner(strings.NewReader("not hex\n")))
	assert.Error(t, err)
	_, err = parsePeaksHex(bufio.NewScanner(strings.NewReader("\n# nothing\n")))
	assert.Error(t, err)
}

// TestCheckAnchorRejectsForeignProof: a proof that commits to some other digest
// must not be accepted as an anchor for this accumulator.
func TestCheckAnchorRejectsForeignProof(t *testing.T) {
	proof, err := os.ReadFile("testdata/foreign.ots")
	if err != nil {
		t.Skip("no testdata/foreign.ots")
	}
	root := accumulatorRoot(peaksFromHex(t, kat39Peaks))
	_, err = checkAnchor(root[:], proof)
	assert.Error(t, err)
}

// TestCheckAnchorKAT39 is the positive case: the proof over the MMR(39)
// accumulator root, anchored in a Bitcoin block.
func TestCheckAnchorKAT39(t *testing.T) {
	proof, err := os.ReadFile("testdata/kat39.ots")
	if err != nil {
		t.Skip("no testdata/kat39.ots")
	}
	root := accumulatorRoot(peaksFromHex(t, kat39Peaks))
	b, err := checkAnchor(root[:], proof)
	require.NoError(t, err)
	assert.Equal(t, uint64(957403), b.Height)
	assert.Len(t, b.MerkleRoot, 32)
}
