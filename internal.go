package musig2

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

// aggregatePublicKeys return the aggregated public key and the weight for me.
func aggregatePublicKeys(ctx *merlin.Transcript, Xs []*sr25519.PublicKey, me *sr25519.PublicKey) (
	*sr25519.PublicKey, *ristretto255.Scalar, error) {

	sortPublicKeys(Xs)

	pkCtx := ctx.Clone()
	for _, v := range Xs { // append L to ctx
		pkCtx.AppendMessage(labelL, v.MustMarshalBinary())
	}

	var a1 *ristretto255.Scalar
	X := ristretto255.NewElement()
	for i, v := range Xs {
		cc := pkCtx.Clone()
		cc.AppendMessage(labelXi, v.MustMarshalBinary())
		ai, err := newChallengingScalar(cc, labelAi)
		if err != nil {
			return nil, nil, fmt.Errorf("generate a_%d: %w", i, err)
		}
		X.Add(X, ristretto255.NewElement().ScalarMult(ai, v.A))

		if bytes.Equal(me.MustMarshalBinary(), v.MustMarshalBinary()) {
			a1 = ai
		}
	}

	outX := new(sr25519.PublicKey)
	if err := outX.UnmarshalBinary(X.Encode(nil)); err != nil {
		return nil, nil, fmt.Errorf("unmarshal public key: %w", err)
	}

	return outX, a1, nil
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
		nonceCtx.AppendMessage(labelRj, v.Encode(buf[:0]))
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
		witnesses[i] = merlin.Witness{Label: labelRandWitness, Body: v}
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
