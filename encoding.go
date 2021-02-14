package musig2

import (
	"fmt"

	"github.com/gtank/ristretto255"
)

func marshalNonces(nonces [NoncesLen]*ristretto255.Element) []byte {
	out := make([]byte, 0, noncesBytesLen)
	for _, v := range nonces {
		out = v.Encode(out)
	}

	return out
}

func marshalSig(R *ristretto255.Element, s *ristretto255.Scalar) []byte {
	var out [64]byte
	R.Encode(out[0:0:32])
	s.Encode(out[32:32:64])

	return out[:]
}

func unmarshalNonces(data []byte) ([NoncesLen]*ristretto255.Element, error) {
	var out, zeros [NoncesLen]*ristretto255.Element

	if len(data) != noncesBytesLen {
		return zeros, fmt.Errorf("length(%d)!=%d: %w", len(data), noncesBytesLen, ErrBadNonces)
	}

	for i := range out {
		out[i] = ristretto255.NewElement()
		if err := out[i].Decode(data[i*32 : (i+1)*32]); err != nil {
			return zeros, fmt.Errorf("%d-th nonce is invalid: %w", i, ErrBadNonces)
		}
	}

	return out, nil
}

func unmarshalSig(sig []byte) (*ristretto255.Element, *ristretto255.Scalar, error) {
	if len(sig) != 64 {
		return nil, nil, fmt.Errorf("expect length 64, got %d: %w", len(sig), ErrBadSig)
	}

	R := ristretto255.NewElement()
	if err := R.Decode(sig[:32]); err != nil {
		return nil, nil, fmt.Errorf("invalid R: %w", err)
	}

	s := ristretto255.NewScalar()
	if err := s.Decode(sig[32:]); err != nil {
		return nil, nil, fmt.Errorf("invalid s: %w", err)
	}

	return R, s, nil
}
