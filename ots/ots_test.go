package ots

import (
	"crypto/sha256"
	"os"
	"strconv"
	"testing"
)

// The fixture is a real OpenTimestamps proof over the note body of a Bitcoin-anchored
// Static CT checkpoint. Its Bitcoin attestation is block 957350, whose Merkle root is
// fcaeee72...cdb3b on the chain (checked against a block explorer 2026-09-18).
const (
	fixtureHeight = 957350
	fixtureRoot   = "fcaeee72588400b910a53d0fbbb6d4d8c671045d9f450636a89f9338670cdb3b"
)

func fixture(t *testing.T) (proof, digest []byte) {
	t.Helper()
	proof, err := os.ReadFile("testdata/tuscolo.ots")
	if err != nil {
		t.Skip("no fixture")
	}
	body, err := os.ReadFile("testdata/tuscolo.txt")
	if err != nil {
		t.Skip("no fixture")
	}
	d := sha256.Sum256(body)
	return proof, d[:]
}

func TestVerifyWalksToBitcoin(t *testing.T) {
	proof, digest := fixture(t)
	p, err := Verify(proof, digest)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	b, ok := p.Bitcoin()
	if !ok {
		t.Fatal("no bitcoin attestation")
	}
	if b.Height != fixtureHeight {
		t.Errorf("height = %d, want %d", b.Height, fixtureHeight)
	}
	if got := b.MerkleRootHex(); got != fixtureRoot {
		t.Errorf("merkle root = %s, want %s", got, fixtureRoot)
	}
}

func TestVerifyRejectsAnotherDigest(t *testing.T) {
	proof, _ := fixture(t)
	if _, err := Verify(proof, make([]byte, 32)); err == nil {
		t.Fatal("accepted a proof for a different digest")
	}
}

// TestVerifyNoticesTampering: flipping any byte must change what the proof says,
// or be rejected outright. A branch that still reaches the same attestations with
// the same values would mean a bit of the proof does not matter.
func TestVerifyNoticesTampering(t *testing.T) {
	proof, digest := fixture(t)
	good, err := Verify(proof, digest)
	if err != nil {
		t.Fatal(err)
	}
	for i := 60; i < len(proof)-1; i += 137 {
		bad := append([]byte(nil), proof...)
		bad[i] ^= 0x01
		p, err := Verify(bad, digest)
		if err != nil {
			continue // rejected outright, fine
		}
		if fingerprint(p) == fingerprint(good) {
			t.Fatalf("byte %d flipped and every attestation stayed the same", i)
		}
	}
}

func TestVerifyRejectsJunk(t *testing.T) {
	if _, err := Verify([]byte("not a proof"), nil); err == nil {
		t.Fatal("accepted junk")
	}
}

func fingerprint(p *Proof) string {
	s := ""
	for _, a := range p.Attestations {
		s += a.Kind + ":" + strconv.FormatUint(a.Height, 10) + ":" + a.MerkleRootHex() + ":" + a.URI + "|"
	}
	return s
}
