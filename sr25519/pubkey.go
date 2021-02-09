package sr25519

import (
	"fmt"

	"github.com/gtank/ristretto255"
)

type PublicKey struct {
	A *ristretto255.Element

	encodedA []byte // 32 bytes canonical encoding of a, see https://ristretto.group/formulas/encoding.html
}

func (pub *PublicKey) MarshalBinary() ([]byte, error) {
	return pub.encodedA, nil
}

func (pub *PublicKey) MustMarshalBinary() []byte {
	return pub.encodedA
}

func (pub *PublicKey) UnmarshalBinary(data []byte) error {
	A := new(ristretto255.Element)
	if err := A.Decode(data); err != nil {
		return fmt.Errorf("decode data: %w(%v)", ErrUnmarshalPublicKey, err)
	}

	pub.A, pub.encodedA = A, A.Encode(nil)
	return nil
}
