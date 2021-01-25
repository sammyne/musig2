package musig

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/gtank/ristretto255"
	"github.com/sammyne/merlin"

	"github.com/sammyne/musig2/sr25519"
)

var (
	labelCommitPK  = []byte("MuSig-aggregate-public_key")
	labelProtoName = []byte("proto-name")
	labelSignC     = []byte("sign:c")
	labelSignPK    = []byte("sign:pk")
	protoName      = []byte("Schnorr-sig")
)

type Commitment = [16]byte
type Reveal = [32 * Rewinds]byte

type Sig struct {
	R [32]byte
	S [32]byte
}

type MuSig struct {
	commitments map[string]Commitment           // public key => commitment
	cosigs      map[string]*ristretto255.Scalar // @TODO: maybe optimise as array
	ctx         *merlin.Transcript
	reveals     map[string][Rewinds]*ristretto255.Element // public key => reveal
	// orderedPubKeys will be in order after all commitments being collected
	orderedPubKeys []*sr25519.PublicKey
	privKey        *sr25519.PrivateKey
	myPubKey       string // in hex
	myR            [Rewinds]*ristretto255.Element
	myr            [Rewinds]*ristretto255.Scalar
	sumR           *ristretto255.Element
	state          State
}

func (s *MuSig) AddCommitment(PK []byte, commitment Commitment) error {
	yHex := hex.EncodeToString(PK)
	if _, ok := s.commitments[yHex]; ok {
		return ErrDoubleCache
	}

	Y, err := unmarshalPublicKey(PK)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	s.commitments[yHex], s.orderedPubKeys = commitment, append(s.orderedPubKeys, Y)

	return nil
}

func (s *MuSig) AddCosig(PK, cosig []byte) error {
	yHex := hex.EncodeToString(PK)
	if _, ok := s.reveals[yHex]; !ok {
		return fmt.Errorf("commitment isn't revealed: %w", ErrUnknownPK)
	} else if _, ok := s.cosigs[yHex]; ok {
		return ErrDoubleCache
	}

	if len(cosig) != CosigLen {
		return fmt.Errorf("%w(wrong length: expect %d, got %d)", ErrInvalidCosig, CosigLen, len(cosig))
	}

	s.cosigs[yHex] = new(ristretto255.Scalar).FromUniformBytes(cosig)

	return nil
}

func (s *MuSig) AddReveal(PK []byte, r Reveal) error {
	yHex := hex.EncodeToString(PK)
	expectC, ok := s.commitments[yHex]
	if !ok {
		return fmt.Errorf("PK isn't committed: %w", ErrUnknownPK)
	} else if _, ok := s.reveals[yHex]; ok {
		return ErrDoubleCache
	}

	var R [Rewinds]*ristretto255.Element
	for i := range R {
		R[i] = new(ristretto255.Element)
		if err := R[i].Decode(r[i*32 : (i+1)*32]); err != nil {
			return fmt.Errorf("%d-th reveal: %w(%v)", i, ErrDecodeReveal, err)
		}
	}

	if gotC, err := newCommitment(R); err != nil {
		return fmt.Errorf("encode commitment: %w", err)
	} else if expectC != gotC {
		return ErrRevealMismatchCommit
	}

	s.reveals[yHex] = R

	return nil
}

func (s *MuSig) OurCommitment() (Commitment, error) {
	if s.state != StateNew {
		err := fmt.Errorf("%w(expect %q, got %q)", ErrInvalidState, StateNew, s.state)
		return Commitment{}, err
	}
	s.state = StateCommit

	return newCommitment(s.myR)
}

func (s *MuSig) OurCosig() ([]byte, error) {
	switch {
	case s.state != StateReveal:
		err := fmt.Errorf("%w(expect %q, got %q)", ErrInvalidState, StateReveal, s.state)
		return nil, err
	case len(s.reveals) < s.PartyLen():
		return nil, fmt.Errorf("miss reveal: expect %d, got %d", s.PartyLen(), len(s.reveals))
	default:
	}
	s.state = StateCosign

	s.ctx.AppendMessage(labelProtoName, protoName)
	s.ctx.AppendMessage(labelSignPK, s.privKey.PublicKey.MustMarshalBinary())

	rewinder := s.rewinder()

	x, Rs := rewinder(&s.privKey.PublicKey), s.reveals[s.myPubKey]
	s.sumR = new(ristretto255.Element).VarTimeMultiScalarMult(x[:], Rs[:])
	s.ctx.AppendMessage(labelSignR, s.sumR.Encode(nil))

	myA, err := s.calcMyWeight()
	if err != nil {
		return nil, fmt.Errorf("calc a: %w", err)
	}

	myS := new(ristretto255.Scalar)

	rewinds := rewinder(&s.privKey.PublicKey)
	for i, v := range s.myr {
		myS.Add(myS, new(ristretto255.Scalar).Multiply(v, rewinds[i]))
	}

	c, err := newChallengingScalar(s.ctx, labelSignC)
	if err != nil {
		return nil, fmt.Errorf("generate c: %w", err)
	}

	c.Multiply(c, myA)
	c.Multiply(c, s.privKey.S)

	myS.Add(myS, c)

	s.cosigs[s.myPubKey] = myS

	return myS.Encode(nil), nil
}

func (s *MuSig) OurReveal() (Reveal, error) {
	if s.state != StateCommit {
		err := fmt.Errorf("%w(expect %q, got %q)", ErrInvalidState, StateCommit, s.state)
		return Reveal{}, err
	}
	s.state = StateReveal

	sortPublicKeys(s.orderedPubKeys)

	var out Reveal
	for i, v := range s.myR {
		v.Encode(out[i*32:])
	}

	return out, nil
}

// PartyLen returns the total peer involved.
func (s *MuSig) PartyLen() int {
	return len(s.orderedPubKeys)
}

func (s *MuSig) PublicKey() *sr25519.PublicKey {
	return &s.privKey.PublicKey
}

// Sign outputs the final aggregated sig.
func (s *MuSig) Sign() ([]byte, error) {
	switch {
	case s.state != StateCosign:
		err := fmt.Errorf("%w(expect %q, got %q)", ErrInvalidState, StateCosign, s.state)
		return nil, err
	case len(s.cosigs) != s.PartyLen():
		return nil, fmt.Errorf("miss co-sig: expect %d, got %d", s.PartyLen(), len(s.cosigs))
	default:
	}

	sumS := new(ristretto255.Scalar)

	for _, v := range s.orderedPubKeys {
		vHex := hex.EncodeToString(v.MustMarshalBinary())
		sumS = sumS.Add(sumS, s.cosigs[vHex])
	}

	var out [64]byte
	s.sumR.Encode(out[:])
	sumS.Encode(out[32:])

	return out[:], nil
}

func Verify(PK []*sr25519.PublicKey, msg, muSig []byte) error {
	panic("todo")
}

func NewMuSig(ctx *merlin.Transcript, rand io.Reader, priv *sr25519.PrivateKey,
	msg []byte) (*MuSig, error) {
	var myr [Rewinds]*ristretto255.Scalar
	for i := range myr {
		var (
			err error
			idx [8]byte
		)

		binary.LittleEndian.PutUint64(idx[:], uint64(i))
		if myr[i], err = randScalar(ctx, rand, priv.Nonce[:], idx[:]); err != nil {
			return nil, fmt.Errorf("fail to generate scalar randomly: %w", err)
		}
	}

	var myR [Rewinds]*ristretto255.Element
	for i, v := range myr {
		myR[i] = ristretto255.NewElement().ScalarBaseMult(v)
	}

	pkHex := hex.EncodeToString(priv.PublicKey.MustMarshalBinary())

	out := &MuSig{
		ctx:         ctx,
		commitments: make(map[string]Commitment),
		cosigs:      make(map[string]*ristretto255.Scalar),
		privKey:     priv,
		myPubKey:    pkHex,
		myR:         myR,
		myr:         myr,
		reveals:     map[string][Rewinds]*ristretto255.Element{pkHex: myR},
		state:       StateNew,
	}

	return out, nil
}
