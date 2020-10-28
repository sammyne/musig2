package sr25519

import (
	"fmt"
	"io"

	"github.com/gtank/ristretto255"
	"github.com/sammyne/merlin"
)

var ctxLabel = []byte("SigningContext")

func newScalarFromMerlinChallenge(transcript *merlin.Transcript, label []byte) (
	*ristretto255.Scalar, error) {
	var s [64]byte
	if err := transcript.ChallengeBytes(label, s[:]); err != nil {
		return nil, fmt.Errorf("fail to read challenge: %w", err)
	}

	out := ristretto255.NewScalar().FromUniformBytes(s[:])
	return out, nil
}

func newSigningTranscript(msg []byte) *merlin.Transcript {
	transcript := merlin.NewTranscript(ctxLabel)
	transcript.AppendMessage(nil, msg)
	return transcript
}

func randScalar(rand io.Reader) (*ristretto255.Scalar, error) {
	var r [64]byte
	if _, err := io.ReadFull(rand, r[:]); err != nil {
		return nil, fmt.Errorf("not enough entropy to make a new scalar: %w", err)
	}

	out := ristretto255.NewScalar().FromUniformBytes(r[:])
	return out, nil
}
