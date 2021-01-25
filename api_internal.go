package musig

import (
	"encoding/hex"

	"github.com/gtank/ristretto255"

	"github.com/sammyne/merlin"
	"github.com/sammyne/musig2/sr25519"
)

var (
	commitmentLabel           = []byte("commitment")
	commitmentSignLabel       = []byte("sign:R")
	commitmentTranscriptLabel = []byte("MuSig-commitment")
	randWitnessLabel          = []byte("MuSigWitness")

	labelPKChoice = []byte("pk-choice")
	labelPKSet    = []byte("pk-set")
	labelR        = []byte("R")
	labelSignR    = []byte("sign:R")
)

type rewindFunc = func(PK *sr25519.PublicKey) [Rewinds]*ristretto255.Scalar

func (s *MuSig) calcMyWeight() (*ristretto255.Scalar, error) {
	// commit public key
	t := merlin.NewTranscript(labelCommitPK)
	for _, v := range s.orderedPubKeys {
		t.AppendMessage(labelPKSet, v.MustMarshalBinary())
	}

	t.AppendMessage(labelPKChoice, s.privKey.MustMarshalBinary())

	return newChallengingScalar(t, nil)
}

func (s *MuSig) rewinder() rewindFunc {
	ctx := s.ctx.Clone()
	for _, v := range s.orderedPubKeys {
		y := v.MustMarshalBinary()
		ctx.AppendMessage(labelPKSet, y)

		Rs := s.reveals[hex.EncodeToString(y)]
		for _, vv := range Rs {
			ctx.AppendMessage(labelR, vv.Encode(nil))
		}
	}

	// @TODO: error handling
	out := func(PK *sr25519.PublicKey) [Rewinds]*ristretto255.Scalar {
		ctx := ctx.Clone()

		y, _ := PK.MarshalBinary()
		ctx.AppendMessage(labelPKChoice, y)

		var ss [Rewinds]*ristretto255.Scalar
		for i := range ss {
			ss[i], _ = newChallengingScalar(ctx, labelR)
		}

		return ss
	}

	return out
}

//func (s *MuSig) sumR(rewind rewindFunc) *ristretto255.Element {
//	x, Rs := rewind(&s.privKey.PublicKey), s.reveals[s.myPubKey]
//
//	return new(ristretto255.Element).VarTimeMultiScalarMult(x[:], Rs[:])
//}
