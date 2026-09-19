package veracity

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/datatrails/veracity/ots"
	"github.com/forestrie/go-merklelog/massifs"
	"github.com/forestrie/go-merklelog/mmr"
	"github.com/urfave/cli/v2"
)

// This file exists to interoperate with OpenTimestamps, and with anchoring
// services such as Markovian Protocol's that commit to one hash per log state.
// The accumulator itself needs no single hash. An OpenTimestamps proof commits
// to one, so the digest here is sha256 over the COSE detached payload the
// checkpoint receipt signs: massifs.DetachedPayload, the raw concatenation of
// the accumulator peaks in descending height order. Stamping that payload means
// the OpenTimestamps proof, the operator's seal and the univocity contract all
// commit to the same bytes.

// accumulatorDigest returns the sha256 an OpenTimestamps proof commits to for a
// peak set.
func accumulatorDigest(peaks [][]byte) [32]byte {
	return sha256.Sum256(massifs.DetachedPayload(peaks))
}

// parsePeaksHex reads peak hashes, one hex string per line, in the order the
// accumulator holds them. Blank lines and # comments are ignored.
func parsePeaksHex(r *bufio.Scanner) ([][]byte, error) {
	var peaks [][]byte
	for r.Scan() {
		line := strings.TrimSpace(r.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		b, err := hex.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("peak %d is not hex: %w", len(peaks), err)
		}
		peaks = append(peaks, b)
	}
	if err := r.Err(); err != nil {
		return nil, err
	}
	if len(peaks) == 0 {
		return nil, errors.New("no peaks read")
	}
	return peaks, nil
}

// checkAnchor verifies an OpenTimestamps proof commits to digest and reports the
// Bitcoin block it is anchored in. It does no network I/O: comparing the
// returned Merkle root with a block header is the caller's step.
func checkAnchor(digest []byte, proof []byte) (ots.Attestation, error) {
	p, err := ots.Verify(proof, digest)
	if err != nil {
		return ots.Attestation{}, err
	}
	b, ok := p.Bitcoin()
	if !ok {
		for _, a := range p.Attestations {
			if a.Kind == "pending" {
				return ots.Attestation{}, fmt.Errorf(
					"proof is pending at %s: it is not yet in a block, run `ots upgrade` and retry", a.URI)
			}
		}
		return ots.Attestation{}, errors.New("proof carries no Bitcoin attestation")
	}
	return b, nil
}

func NewAccumulatorOTSHashCmd() *cli.Command {
	return &cli.Command{
		Name:  "accumulator-ots-hash",
		Usage: "Print the sha256 an OpenTimestamps proof commits to for an accumulator, and optionally check a proof over it",
		Description: `For interoperating with OpenTimestamps, and with anchoring services such as
Markovian Protocol's. The accumulator needs no single hash; an OpenTimestamps
proof commits to one. This prints sha256 over the detached payload of the
accumulator peaks - the same bytes massifs.DetachedPayload produces and the
univocity contract verifies. Stamping that payload with the stock ots client
gives a proof over this digest. With --ots it reads an OpenTimestamps proof,
checks in process that the proof commits to exactly this digest, and prints the
Bitcoin block and the Merkle root that block must have. It fetches no block
headers: existence and ordering against the chain, not consistency or
append-only.`,
		Flags: []cli.Flag{
			&cli.Int64Flag{
				Name: "mmrindex", Aliases: []string{"i"},
				Usage: "read the peaks for this mmr index from the log",
			},
			&cli.StringFlag{
				Name:  "peaks",
				Usage: "read the peaks from `FILE` instead of the log, one hex hash per line ('-' for stdin)",
			},
			&cli.StringFlag{
				Name:  "ots",
				Usage: "check the OpenTimestamps proof in `FILE` commits to the digest",
			},
		},
		Action: func(cCtx *cli.Context) error {
			cmd := &CmdCtx{}
			if err := cfgLogging(cmd, cCtx); err != nil {
				return err
			}

			var peaks [][]byte
			var err error

			if peaksFile := cCtx.String("peaks"); peaksFile != "" {
				f := os.Stdin
				if peaksFile != "-" {
					f, err = os.Open(peaksFile)
					if err != nil {
						return err
					}
					defer f.Close()
				}
				peaks, err = parsePeaksHex(bufio.NewScanner(f))
				if err != nil {
					return err
				}
			} else {
				if err = cfgMassifFmt(cmd, cCtx); err != nil {
					return err
				}
				reader, err := newMassifReader(cmd, cCtx)
				if err != nil {
					return err
				}
				mmrIndex := cCtx.Uint64("mmrindex")
				massifHeight := cmd.MassifFmt.MassifHeight
				massifIndex := uint32(massifs.MassifIndexFromMMRIndex(massifHeight, mmrIndex))
				massif, err := massifs.GetMassifContext(cCtx.Context, reader, massifIndex)
				if err != nil {
					return err
				}
				peaks, err = mmr.PeakHashes(&massif, mmrIndex)
				if err != nil {
					return err
				}
			}

			digest := accumulatorDigest(peaks)
			fmt.Printf("peaks: %d\n", len(peaks))
			fmt.Printf("accumulator digest: %x\n", digest)

			otsFile := cCtx.String("ots")
			if otsFile == "" {
				return nil
			}
			proof, err := os.ReadFile(otsFile)
			if err != nil {
				return err
			}
			b, err := checkAnchor(digest[:], proof)
			if err != nil {
				return fmt.Errorf("anchor: %w", err)
			}
			fmt.Printf("anchored in bitcoin block %d\n", b.Height)
			fmt.Printf("that block's merkle root must be %s\n", b.MerkleRootHex())
			return nil
		},
	}
}
