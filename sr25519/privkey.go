package sr25519

import (
	"fmt"
	"io"

	"github.com/gtank/ristretto255"
)

// PrivateKey represents an sr25519 private key.
type PrivateKey struct {
	// PublicKey is the public key paired with this private key.
	PublicKey

	// S is the secret scalar.
	S *ristretto255.Scalar
	// Nonce is the seed for deriving the nonces used in signing.
	Nonce [32]byte
}

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() PublicKey {
	return priv.PublicKey
}

// GenerateKey generates a public and private key pair.
func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	var r [64 + 32]byte
	if _, err := io.ReadFull(rand, r[:]); err != nil {
		return nil, fmt.Errorf("not enough entropy: %w", err)
	}

	s := ristretto255.NewScalar().FromUniformBytes(r[:64])

	var nonce [32]byte
	copy(nonce[:], r[64:])

	A := ristretto255.NewElement().ScalarBaseMult(s)
	pub := PublicKey{A: A, encodedA: A.Encode(nil)}

	priv := &PrivateKey{PublicKey: pub, S: s, Nonce: nonce}

	return priv, nil
}
