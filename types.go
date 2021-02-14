package musig2

import (
	"github.com/gtank/ristretto255"
	"github.com/sammyne/musig2/sr25519"
)

type weightedPublicKey struct {
	Y *sr25519.PublicKey
	W *ristretto255.Scalar
}
