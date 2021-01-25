package musig

import (
	"bytes"
	"fmt"
	"io"
	"sort"

	"github.com/gtank/ristretto255"
	"github.com/sammyne/merlin"

	"github.com/sammyne/musig2/sr25519"
)

func newChallengingScalar(t *merlin.Transcript, label []byte) (*ristretto255.Scalar, error) {
	var buf [64]byte
	if err := t.ChallengeBytes(label, buf[:]); err != nil {
		return nil, fmt.Errorf("generate challenge bytes: %w", err)
	}

	out := new(ristretto255.Scalar).FromUniformBytes(buf[:])
	return out, nil
}

func newCommitment(nonce [Rewinds]*ristretto255.Element) (Commitment, error) {
	transcript := merlin.NewTranscript(commitmentTranscriptLabel)

	var b [32]byte
	for _, v := range nonce {
		v.Encode(b[:])
		transcript.AppendMessage(commitmentSignLabel, b[:])
	}

	var out Commitment
	if err := transcript.ChallengeBytes(commitmentLabel, out[:]); err != nil {
		return Commitment{}, fmt.Errorf("generate challenge bytes: %w(%v)", ErrGenerateChallenge, err)
	}

	return out, nil
}

func randScalar(t *merlin.Transcript, r io.Reader, nonces ...[]byte) (*ristretto255.Scalar, error) {
	witnesses := make([]merlin.Witness, len(nonces))
	for i, v := range nonces {
		witnesses[i] = merlin.Witness{Label: randWitnessLabel, Body: v}
	}

	rand, err := merlin.NewRand(t, r, witnesses...)
	if err != nil {
		return nil, fmt.Errorf("new RNG: %w(%v)", ErrRand, err)
	}

	var b [64]byte
	if _, err := io.ReadFull(rand, b[:]); err != nil {
		return nil, fmt.Errorf("read random bytes: %w(%v)", ErrRand, err)
	}

	out := new(ristretto255.Scalar).FromUniformBytes(b[:])
	return out, nil
}

// @TODO: to be optimise
func sortPublicKeys(PKs []*sr25519.PublicKey) {
	sort.Slice(PKs, func(i, j int) bool {
		y1, _ := PKs[i].MarshalBinary()
		y2, _ := PKs[j].MarshalBinary()
		return bytes.Compare(y1, y2) == -1
	})
}

func unmarshalPublicKey(b []byte) (*sr25519.PublicKey, error) {
	out := new(sr25519.PublicKey)
	if err := out.UnmarshalBinary(b); err != nil {
		return nil, err
	}

	return out, nil
}
