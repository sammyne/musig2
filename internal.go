package musig

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/gtank/ristretto255"
	"github.com/sammyne/merlin"

	"github.com/sammyne/musig2/sr25519"
)

type nonceWeightCalcFunc = func(i int) *ristretto255.Scalar

func marshalElements(vals []*ristretto255.Element) []byte {
	out := make([]byte, len(vals)*32)
	for i, v := range vals {
		v.Encode(out[i*32:])
	}

	return out
}

func mustNewScalarOne() *ristretto255.Scalar {
	var oneLE [32]byte
	oneLE[0] = 1

	out := ristretto255.NewScalar()
	if err := out.Decode(oneLE[:]); err != nil {
		panic("unexpected decode scalar one")
	}

	return out
}

func newChallengingScalar(t *merlin.Transcript, label []byte) (*ristretto255.Scalar, error) {
	var buf [64]byte
	if err := t.ChallengeBytes(label, buf[:]); err != nil {
		return nil, fmt.Errorf("generate challenge bytes: %w", err)
	}

	out := new(ristretto255.Scalar).FromUniformBytes(buf[:])
	return out, nil
}

func newNoncesWeightCalculator(ctx *merlin.Transcript,
	Rj [NoncesLen]*ristretto255.Element) nonceWeightCalcFunc {
	nonceCtx := ctx.Clone()

	var buf [32]byte
	for _, v := range Rj {
		nonceCtx.AppendMessage(labelNonceRj, v.Encode(buf[:0]))
	}

	out := func(i int) *ristretto255.Scalar {
		var idx [2]byte
		binary.LittleEndian.PutUint16(idx[:], uint16(i))
		s, err := newChallengingScalar(nonceCtx.Clone(), idx[:])
		if err != nil {
			panic(fmt.Sprintf("generate b(%d): %v", i, err))
		}

		return s
	}

	return out
}

func randScalar(t *merlin.Transcript, r io.Reader, nonces ...[]byte) (*ristretto255.Scalar, error) {
	witnesses := make([]merlin.Witness, len(nonces))
	for i, v := range nonces {
		witnesses[i] = merlin.Witness{Label: randWitnessLabel, Body: v}
	}

	rand, err := merlin.NewRand(t, r, witnesses...)
	if err != nil {
		return nil, fmt.Errorf("new RNG: %w(%v)", ErrRand, err)
	}

	var b [64]byte
	if _, err := io.ReadFull(rand, b[:]); err != nil {
		return nil, fmt.Errorf("read random bytes: %w(%v)", ErrRand, err)
	}

	out := new(ristretto255.Scalar).FromUniformBytes(b[:])
	return out, nil
}

// @TODO: to be optimise
func sortPublicKeys(PKs []*sr25519.PublicKey) {
	sort.Slice(PKs, func(i, j int) bool {
		y1, _ := PKs[i].MarshalBinary()
		y2, _ := PKs[j].MarshalBinary()
		return bytes.Compare(y1, y2) == -1
	})
}

func unmarshalPublicKey(b []byte) (*sr25519.PublicKey, error) {
	out := new(sr25519.PublicKey)
	if err := out.UnmarshalBinary(b); err != nil {
		return nil, err
	}

	return out, nil
}
