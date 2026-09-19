// Package ots verifies OpenTimestamps detached proofs in process, with nothing
// outside the Go standard library: no cgo, no new module dependency, and no call
// out to the stock `ots` client.
//
// A proof is a tree of operations applied to a starting digest. Walking it to a
// Bitcoin attestation yields two facts: the block height the proof claims, and
// the Merkle root that block must have if the proof is honest. This package
// produces both. It does not fetch block headers, so it proves the arithmetic
// of the proof, not that the block exists: the caller compares MerkleRoot
// against the header it trusts.
package ots

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

var magic = []byte("\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94")

// Attestation tags, as serialized in a proof.
var (
	tagBitcoin  = [8]byte{0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01}
	tagPending  = [8]byte{0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e}
	tagLitecoin = [8]byte{0x06, 0x86, 0x9a, 0x0d, 0x73, 0xd7, 0x1b, 0x45}
	tagEthereum = [8]byte{0x30, 0xfe, 0x80, 0x87, 0xb5, 0xc7, 0xea, 0xd7}
)

// Operation tags.
const (
	opAppend    = 0xf0
	opPrepend   = 0xf1
	opReverse   = 0xf2
	opHexlify   = 0xf3
	opSHA1      = 0x02
	opRIPEMD160 = 0x03
	opSHA256    = 0x08
	opKECCAK256 = 0x67
)

// maxOps bounds the work a hostile proof can ask for.
const maxOps = 10000

// Attestation is one leaf of the proof tree: a claim about where a digest ended up.
type Attestation struct {
	Kind string // "bitcoin", "litecoin", "ethereum", "pending", or "unknown:<hex tag>"

	// Height is the block height, for chain attestations.
	Height uint64

	// MerkleRoot is the value the walk arrived at. For a Bitcoin attestation this
	// is the block's Merkle root in internal (little-endian) byte order — the
	// caller must compare it with the header it trusts. Nothing here fetches it.
	MerkleRoot []byte

	// URI is the calendar address, for a pending attestation.
	URI string
}

// MerkleRootHex returns the Merkle root in the display order block explorers use.
func (a Attestation) MerkleRootHex() string {
	b := make([]byte, len(a.MerkleRoot))
	for i, c := range a.MerkleRoot {
		b[len(b)-1-i] = c
	}
	return hex.EncodeToString(b)
}

// Proof is a parsed detached proof.
type Proof struct {
	// FileDigest is the digest the proof starts from: the hash of the stamped file.
	FileDigest []byte
	// HashOp names the hash the digest was made with ("sha256", "sha1").
	HashOp string
	// Attestations are the leaves, in the order the walk reached them.
	Attestations []Attestation
}

// Bitcoin returns the earliest Bitcoin attestation in the proof.
func (p *Proof) Bitcoin() (Attestation, bool) {
	best := Attestation{}
	found := false
	for _, a := range p.Attestations {
		if a.Kind != "bitcoin" {
			continue
		}
		if !found || a.Height < best.Height {
			best, found = a, true
		}
	}
	return best, found
}

type reader struct {
	b   []byte
	i   int
	ops int
}

var errTruncated = errors.New("ots: proof ends mid-value")

func (r *reader) byteAt() (byte, error) {
	if r.i >= len(r.b) {
		return 0, errTruncated
	}
	c := r.b[r.i]
	r.i++
	return c, nil
}

func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || r.i+n > len(r.b) {
		return nil, errTruncated
	}
	v := r.b[r.i : r.i+n]
	r.i += n
	return v, nil
}

// varuint is OpenTimestamps' base-128 little-endian integer.
func (r *reader) varuint() (uint64, error) {
	var v uint64
	var shift uint
	for {
		c, err := r.byteAt()
		if err != nil {
			return 0, err
		}
		if shift >= 64 {
			return 0, errors.New("ots: varuint overflows 64 bits")
		}
		v |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, nil
		}
		shift += 7
	}
}

func (r *reader) varbytes() ([]byte, error) {
	n, err := r.varuint()
	if err != nil {
		return nil, err
	}
	if n > uint64(len(r.b)) {
		return nil, errTruncated
	}
	return r.take(int(n))
}

// Verify parses a detached proof and walks every branch.
//
// If fileDigest is non-nil it must equal the digest the proof starts from;
// otherwise the proof belongs to a different file and Verify fails.
func Verify(proof, fileDigest []byte) (*Proof, error) {
	if !bytes.HasPrefix(proof, magic) {
		return nil, errors.New("ots: not an OpenTimestamps detached proof")
	}
	r := &reader{b: proof, i: len(magic)}

	version, err := r.varuint()
	if err != nil {
		return nil, err
	}
	if version != 1 {
		return nil, fmt.Errorf("ots: unsupported proof version %d", version)
	}

	hashTag, err := r.byteAt()
	if err != nil {
		return nil, err
	}
	name, size, err := hashOp(hashTag)
	if err != nil {
		return nil, err
	}
	digest, err := r.take(size)
	if err != nil {
		return nil, err
	}
	if fileDigest != nil && !bytes.Equal(fileDigest, digest) {
		return nil, fmt.Errorf("ots: proof commits to %x, not to the digest given (%x)",
			digest, fileDigest)
	}

	p := &Proof{FileDigest: append([]byte(nil), digest...), HashOp: name}
	if err := r.walk(append([]byte(nil), digest...), p); err != nil {
		return nil, err
	}
	if r.i != len(r.b) {
		return nil, fmt.Errorf("ots: %d trailing bytes after the proof", len(r.b)-r.i)
	}
	if len(p.Attestations) == 0 {
		return nil, errors.New("ots: proof carries no attestation")
	}
	return p, nil
}

// walk consumes one timestamp: zero or more forked branches, then a final one.
func (r *reader) walk(msg []byte, p *Proof) error {
	for {
		tag, err := r.byteAt()
		if err != nil {
			return err
		}
		if tag != 0xff {
			return r.branch(tag, msg, p)
		}
		if err := r.branch2(msg, p); err != nil {
			return err
		}
	}
}

// branch2 reads the tag of a forked branch and follows it with a copy of msg.
func (r *reader) branch2(msg []byte, p *Proof) error {
	tag, err := r.byteAt()
	if err != nil {
		return err
	}
	return r.branch(tag, append([]byte(nil), msg...), p)
}

// branch follows one branch: an attestation ends it, an operation continues it.
func (r *reader) branch(tag byte, msg []byte, p *Proof) error {
	if tag == 0x00 {
		return r.attestation(msg, p)
	}
	r.ops++
	if r.ops > maxOps {
		return fmt.Errorf("ots: proof asks for more than %d operations", maxOps)
	}
	next, err := r.apply(tag, msg)
	if err != nil {
		return err
	}
	return r.walk(next, p)
}

func (r *reader) attestation(msg []byte, p *Proof) error {
	raw, err := r.take(8)
	if err != nil {
		return err
	}
	var tag [8]byte
	copy(tag[:], raw)
	payload, err := r.varbytes()
	if err != nil {
		return err
	}
	a := Attestation{MerkleRoot: msg}
	switch tag {
	case tagBitcoin, tagLitecoin, tagEthereum:
		a.Kind = map[[8]byte]string{tagBitcoin: "bitcoin", tagLitecoin: "litecoin", tagEthereum: "ethereum"}[tag]
		h, err := (&reader{b: payload}).varuint()
		if err != nil {
			return fmt.Errorf("ots: %s attestation has no block height: %w", a.Kind, err)
		}
		a.Height = h
	case tagPending:
		a.Kind = "pending"
		uri, err := (&reader{b: payload}).varbytes()
		if err == nil {
			a.URI = string(uri)
		}
	default:
		a.Kind = "unknown:" + hex.EncodeToString(tag[:])
	}
	p.Attestations = append(p.Attestations, a)
	return nil
}

func (r *reader) apply(tag byte, msg []byte) ([]byte, error) {
	switch tag {
	case opAppend:
		arg, err := r.varbytes()
		if err != nil {
			return nil, err
		}
		return append(append([]byte(nil), msg...), arg...), nil
	case opPrepend:
		arg, err := r.varbytes()
		if err != nil {
			return nil, err
		}
		return append(append([]byte(nil), arg...), msg...), nil
	case opSHA256:
		s := sha256.Sum256(msg)
		return s[:], nil
	case opSHA1:
		s := sha1.Sum(msg)
		return s[:], nil
	case opReverse:
		out := make([]byte, len(msg))
		for i, c := range msg {
			out[len(out)-1-i] = c
		}
		return out, nil
	case opHexlify:
		return []byte(hex.EncodeToString(msg)), nil
	case opRIPEMD160:
		return nil, errors.New("ots: proof uses RIPEMD160, which this verifier does not implement")
	case opKECCAK256:
		return nil, errors.New("ots: proof uses KECCAK256, which this verifier does not implement")
	default:
		return nil, fmt.Errorf("ots: unknown operation 0x%02x", tag)
	}
}

func hashOp(tag byte) (string, int, error) {
	switch tag {
	case opSHA256:
		return "sha256", sha256.Size, nil
	case opSHA1:
		return "sha1", sha1.Size, nil
	case opRIPEMD160:
		return "", 0, errors.New("ots: RIPEMD160 file digests are not supported")
	case opKECCAK256:
		return "", 0, errors.New("ots: KECCAK256 file digests are not supported")
	default:
		return "", 0, fmt.Errorf("ots: unknown file hash operation 0x%02x", tag)
	}
}

// MerkleRootFromHeader pulls the Merkle root out of an 80-byte Bitcoin block
// header, in the same internal byte order Attestation.MerkleRoot uses.
func MerkleRootFromHeader(header []byte) ([]byte, error) {
	if len(header) != 80 {
		return nil, fmt.Errorf("ots: a Bitcoin block header is 80 bytes, got %d", len(header))
	}
	_ = binary.LittleEndian.Uint32(header[:4]) // version, unused
	return append([]byte(nil), header[36:68]...), nil
}
