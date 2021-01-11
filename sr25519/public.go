package sr25519

import (
	"fmt"

	"github.com/gtank/ristretto255"
)

type PublicKey struct {
	a *ristretto255.Element

	encodedA []byte // 32 bytes canonical encoding of a, see https://ristretto.group/formulas/encoding.html
}

func (pub *PublicKey) MarshalBinary() ([]byte, error) {
	return pub.encodedA, nil
}

func (pub *PublicKey) UnmarshalBinary(data []byte) error {
	a := new(ristretto255.Element)
	if err := a.Decode(data); err != nil {
		return fmt.Errorf("decode data: %w", err)
	}

	pub.a, pub.encodedA = a, a.Encode(nil)
	return nil
}
