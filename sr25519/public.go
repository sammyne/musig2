package sr25519

import "github.com/gtank/ristretto255"

type PublicKey struct {
	a *ristretto255.Element

	encoded []byte // 32 bytes canonical encoding of a, see https://ristretto.group/formulas/encoding.html
}

func (pub *PublicKey) MarshalBinary() ([]byte, error) {
	return pub.encoded, nil
}

//func (pub *Pub)
