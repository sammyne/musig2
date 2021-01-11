package musig

import (
	"github.com/sammyne/merlin"
	"github.com/sammyne/musig/sr25519"
)

type MuSig struct {
}

func (s *MuSig) AddCommitment(PK, commitment []byte) error {
	panic("todo")
}

func (s *MuSig) AddCosig(PK, cosig []byte) error {
	panic("todo")
}

func (s *MuSig) AddReveal(PK, reveal []byte) error {
	panic("todo")
}

func (s *MuSig) OurCommitment() []byte {
	panic("todo")
}

func (s *MuSig) OurCosig() ([]byte, error) {
	panic("todo")
}

func (s *MuSig) OurReveal() ([]byte, error) {
	panic("todo")
}

// Sign outputs the final aggregated sig.
func (s *MuSig) Sign() ([]byte, error) {
	panic("todo")
}

func VerifyMuSig(PK []*sr25519.PublicKey, msg, sig []byte) error {
	panic("todo")
}

func NewMuSig(ctx *merlin.Transcript, msg []byte) *MuSig {
	panic("todo")
}
