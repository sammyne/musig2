package sr25519

import (
	"fmt"
	"io"

	"github.com/gtank/ristretto255"
	"github.com/sammyne/merlin"

	"github.com/sammyne/musig2/bytes"
)

const SigLen = 64

var (
	proto               = []byte("Schnorr-sig")
	protoLabel          = []byte("proto")
	signPubKeyLabel     = []byte("sign:pk")
	signingWitnessLabel = []byte("signing")
	signRLabel          = []byte("sign:R")
	signCLabel          = []byte("sign:c")
)

type Sig struct {
	R *ristretto255.Element
	S *ristretto255.Scalar
}

func (s *Sig) MarshalBinary() (data []byte, err error) {
	var out [64]byte
	s.R.Encode(out[:32])
	s.S.Encode(out[32:])

	return out[:], nil
}

func (s *Sig) UnmarshalBinary(data []byte) error {
	if len(data) != SigLen {
		return fmt.Errorf("invalid sig length: expect %d, got %d", SigLen, len(data))
	}

	s.R = ristretto255.NewElement()
	if err := s.R.Decode(data[:32]); err != nil {
		return fmt.Errorf("fail to decode R: %w", err)
	}

	s.S = ristretto255.NewScalar()
	if err := s.S.Decode(data[32:]); err != nil {
		return fmt.Errorf("fail to decode s: %w", err)
	}

	return nil
}

func MerlinSign(rand io.Reader, priv *PrivateKey, transcript *merlin.Transcript) (*Sig, error) {
	transcript.AppendMessage(protoLabel, proto)

	A, _ := priv.PublicKey.MarshalBinary()
	transcript.AppendMessage(signPubKeyLabel, A)

	witness := merlin.Witness{Label: signingWitnessLabel, Body: bytes.Copy(priv.Nonce[:])}
	rng, err := merlin.NewRand(transcript, rand, witness)
	if err != nil {
		return nil, fmt.Errorf("fail to new RNG: %w", err)
	}

	r, err := randScalar(rng)
	if err != nil {
		return nil, fmt.Errorf("fail to generate scalar randomly: %w", err)
	}
	defer r.Zero()

	R := ristretto255.NewElement().ScalarBaseMult(r)
	transcript.AppendMessage(signRLabel, R.Encode(nil))

	c, err := newScalarFromMerlinChallenge(transcript, signCLabel)
	if err != nil {
		return nil, fmt.Errorf("fail to compute c: %w", err)
	}

	s := c.Multiply(c, priv.S) // cx
	s.Add(s, r)                // cx+r

	out := &Sig{R: R, S: s}
	return out, nil
}

func MerlinVerify(pub *PublicKey, transcript *merlin.Transcript, sig *Sig) bool {
	transcript.AppendMessage(protoLabel, proto)

	A, _ := pub.MarshalBinary()
	transcript.AppendMessage(signPubKeyLabel, A)

	transcript.AppendMessage(signRLabel, sig.R.Encode(nil))

	c, err := newScalarFromMerlinChallenge(transcript, signCLabel)
	if err != nil {
		return false
	}

	negA := ristretto255.NewElement().Negate(pub.A)
	R := ristretto255.NewElement().VarTimeDoubleScalarBaseMult(c, negA, sig.S)

	return R.Equal(sig.R) == 1
}

func Sign(rand io.Reader, priv *PrivateKey, msg []byte) (*Sig, error) {
	return MerlinSign(rand, priv, newSigningTranscript(msg))
}

func Verify(pub *PublicKey, msg []byte, sig *Sig) bool {
	return MerlinVerify(pub, newSigningTranscript(msg), sig)
}
