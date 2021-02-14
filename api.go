package musig2

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/gtank/ristretto255"
	"github.com/sammyne/merlin"

	"github.com/sammyne/musig2/sr25519"
)

var (
	labelProtoName = []byte("proto-name")
	labelNonceRj   = []byte("nonce:Rj")
	labelNoncePK   = []byte("nonce:aggregate-public_key")
	protoName      = []byte("Schnorr-sig")

	labelPKChoice    = []byte("pk-choice")
	labelPKSet       = []byte("pk-set")
	labelRandWitness = []byte("musig2-witness")
	labelSignR       = []byte("sign:R")
)

type Sig struct {
	R [32]byte
	S [32]byte
}

type MuSig2 struct {
	Rs map[string][NoncesLen]*ristretto255.Element // hex(public key) => nonces list

	cosigs map[string]*ristretto255.Scalar // @TODO: maybe optimise as array
	ctx    *merlin.Transcript
	// orderedPubKeys will be in order before co-signing
	orderedPubKeys []*sr25519.PublicKey
	privKey        *sr25519.PrivateKey
	pkHex          string // in hex
	r1             [NoncesLen]*ristretto255.Scalar
	sumR           *ristretto255.Element
	state          State
}

func (s *MuSig2) AddOtherNonces(PK, nonces []byte) error {
	if s.state != StateNonceCollecting {
		return fmt.Errorf("%w(expect %q, got %q)", ErrInvalidState, StateNonceCollecting, s.state)
	}

	pkHex := hex.EncodeToString(PK)
	if _, ok := s.Rs[pkHex]; ok {
		return ErrDoubleCache
	}

	Y, err := unmarshalPublicKey(PK)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	if len(nonces) != 32*NoncesLen {
		return fmt.Errorf("invalid nonces length(%d), expect %d: %w",
			len(nonces), 32*NoncesLen, ErrBadNonces)
	}

	var otherR [NoncesLen]*ristretto255.Element
	for i := range otherR {
		otherR[i] = ristretto255.NewElement()
		if err := otherR[i].Decode(nonces[i*32 : (i+1)*32]); err != nil {
			return fmt.Errorf("%d-th nonce is invalid: %w", i, ErrBadNonces)
		}
	}

	s.Rs[pkHex], s.orderedPubKeys = otherR, append(s.orderedPubKeys, Y)

	return nil
}

func (s *MuSig2) AddOtherCosig(PK, cosig []byte) error {
	if s.state != StateCosigning {
		return fmt.Errorf("%w(expect %q, got %q)", ErrInvalidState, StateCosigning, s.state)
	}

	yHex := hex.EncodeToString(PK)
	if _, ok := s.Rs[yHex]; !ok {
		return fmt.Errorf("nonces ain't added: %w", ErrUnknownPK)
	} else if _, ok := s.cosigs[yHex]; ok {
		return ErrDoubleCache
	}

	si := new(ristretto255.Scalar)
	if err := si.Decode(cosig); err != nil {
		return ErrInvalidCosig
	}

	s.cosigs[yHex] = si

	return nil
}

func (s *MuSig2) OurCosig() ([]byte, error) {
	if s.state != StateNonceCollecting {
		err := fmt.Errorf("%w(expect %q, got %q)", ErrInvalidState, StateNonceCollecting, s.state)
		return nil, err
	}
	s.state = StateCosigning

	X, a1, err := aggregatePublicKeys(s.ctx, s.orderedPubKeys, &s.privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("aggregate public key: %w", err)
	}
	s.ctx.AppendMessage(labelNoncePK, X.MustMarshalBinary())

	//fmt.Println("------")
	//for k, v := range s.Rs {
	//	fmt.Println(" PK", k)
	//	fmt.Println("  R0", v[0])
	//	fmt.Println("  R1", v[1])
	//}
	//fmt.Println("------")

	// calc R_j
	var Rj [NoncesLen]*ristretto255.Element
	//fmt.Println("------")
	for j := range Rj {
		Rj[j] = ristretto255.NewElement()
		for _, v := range s.Rs {
			Rj[j].Add(Rj[j], v[j])
		}
		//fmt.Printf("R[%d] = %s\n", j, Rj[j])
	}
	//fmt.Println("------")

	// calc b_j
	calcNoncesWeight := newNoncesWeightCalculator(s.ctx, Rj)
	var b [NoncesLen]*ristretto255.Scalar
	b[0] = mustNewScalarOne()
	//fmt.Println("------")
	//fmt.Printf("b[0] = %s\n", b[0])
	for j := 1; j < NoncesLen; j++ {
		b[j] = calcNoncesWeight(j)
		//fmt.Printf("b[%d] = %s\n", j, b[j])
	}
	//fmt.Println("------")

	s.sumR = ristretto255.NewElement().VarTimeMultiScalarMult(b[:], Rj[:])

	var buf [32]byte
	s.ctx.AppendMessage(labelSignR, s.sumR.Encode(buf[:0]))

	c, err := randScalar(s.ctx, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("calc c: %w(%v)", ErrRand, err)
	}

	s1 := ristretto255.NewScalar().Multiply(c, a1)
	s1.Multiply(s1, s.privKey.S)

	rbSum := ristretto255.NewScalar()
	for i, v := range s.r1 {
		rbSum.Add(rbSum, ristretto255.NewScalar().Multiply(v, b[i]))
	}
	s1.Add(s1, rbSum)

	s.cosigs[s.pkHex] = s1

	return s1.Encode(buf[:0]), nil
}

func (s *MuSig2) OurNonces() ([]byte, error) {
	if s.state != StateNew {
		return nil, fmt.Errorf("%w(expect %q, got %q)", ErrInvalidState, StateNew, s.state)
	}
	s.state = StateNonceCollecting

	s.orderedPubKeys = append(s.orderedPubKeys, &s.privKey.PublicKey)

	R := s.Rs[s.pkHex]

	//fmt.Println("------")
	//fmt.Println(" R0 =", R[0])
	//fmt.Println(" R1 =", R[1])
	//fmt.Println("------")

	return marshalElements(R[:]), nil
}

// PartyLen returns the total peer involved.
func (s *MuSig2) PartyLen() int {
	return len(s.orderedPubKeys)
}

func (s *MuSig2) PublicKey() *sr25519.PublicKey {
	return &s.privKey.PublicKey
}

// Sign outputs the final aggregated sig.
func (s *MuSig2) Sign() ([]byte, error) {
	switch {
	case s.state != StateCosigning:
		return nil, fmt.Errorf("%w(expect %q, got %q)", ErrInvalidState, StateCosigning, s.state)
	case len(s.cosigs) != s.PartyLen():
		return nil, fmt.Errorf("miss co-sig: expect %d, got %d", s.PartyLen(), len(s.cosigs))
	default:
	}

	sumS := new(ristretto255.Scalar)
	for _, v := range s.cosigs {
		sumS.Add(sumS, v)
	}

	//fmt.Println("R", s.sumR)
	//fmt.Println("s", sumS)

	return marshalSig(s.sumR, sumS), nil
}

func MerlinVerify(Xs []*sr25519.PublicKey, msg *merlin.Transcript, sig []byte) error {
	R, s, err := unmarshalSig(sig)
	if err != nil {
		return fmt.Errorf("invalid sig: %w", err)
	}

	msg.AppendMessage(labelProtoName, protoName)

	X, _, err := aggregatePublicKeys(msg, Xs, Xs[0])
	if err != nil {
		return fmt.Errorf("aggregate public key: %w", err)
	}
	msg.AppendMessage(labelNoncePK, X.MustMarshalBinary())

	var buf [32]byte
	msg.AppendMessage(labelSignR, R.Encode(buf[:0]))

	c, err := randScalar(msg, rand.Reader)
	if err != nil {
		return fmt.Errorf("calc c: %w", err)
	}

	RXc := ristretto255.NewElement().ScalarMult(c, X.A)
	RXc.Add(RXc, R)

	sG := ristretto255.NewElement().ScalarBaseMult(s)
	if sG.Equal(RXc) == 1 {
		return ErrBadSig
	}

	return nil
}

func NewMuSig2(rand io.Reader, priv *sr25519.PrivateKey, msg *merlin.Transcript) (*MuSig2, error) {
	var r [NoncesLen]*ristretto255.Scalar
	for i := range r {
		var err error
		var idx [8]byte

		binary.LittleEndian.PutUint64(idx[:], uint64(i))
		// @dev msg won't be altered
		if r[i], err = randScalar(msg, rand, priv.Nonce[:], idx[:]); err != nil {
			return nil, fmt.Errorf("fail to generate scalar randomly: %w", err)
		}
	}

	var R [NoncesLen]*ristretto255.Element
	for i, v := range r {
		R[i] = ristretto255.NewElement().ScalarBaseMult(v)
	}

	pkHex := hex.EncodeToString(priv.PublicKey.MustMarshalBinary())

	msg.AppendMessage(labelProtoName, protoName)

	out := &MuSig2{
		Rs: map[string][NoncesLen]*ristretto255.Element{pkHex: R},

		ctx:     msg,
		cosigs:  make(map[string]*ristretto255.Scalar),
		privKey: priv,
		pkHex:   pkHex,
		r1:      r,
		state:   StateNew,
	}

	return out, nil
}
