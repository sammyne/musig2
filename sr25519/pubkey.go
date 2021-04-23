package sr25519

import (
	"fmt"

	"github.com/gtank/ristretto255"
)

// PublicKey represents an sr25519 public key.
type PublicKey struct {
	A *ristretto255.Element

	encodedA []byte // 32 bytes canonical encoding of a, see https://ristretto.group/formulas/encoding.html
}

// MarshalBinary marshals the public key into binary format.
func (pub *PublicKey) MarshalBinary() ([]byte, error) {
	return pub.encodedA, nil
}

// MustMarshalBinary is the variant of MarshalBinary, which will panic if any error.
func (pub *PublicKey) MustMarshalBinary() []byte {
	return pub.encodedA
}

// UnmarshalBinary unmarshals this public key from the given data.
func (pub *PublicKey) UnmarshalBinary(data []byte) error {
	A := new(ristretto255.Element)
	if err := A.Decode(data); err != nil {
		return fmt.Errorf("decode data: %w(%v)", ErrUnmarshalPublicKey, err)
	}

	pub.A, pub.encodedA = A, A.Encode(nil)
	return nil
}
