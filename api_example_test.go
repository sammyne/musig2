package musig2_test

import (
	"bytes"
	mathrand "math/rand"

	"github.com/sammyne/musig2"
	"github.com/sammyne/musig2/sr25519"
)

func ExampleVerify() {
	msg := []byte("hello-world")

	mRand := mathrand.New(mathrand.NewSource(123))

	privA, err := sr25519.GenerateKey(mRand)
	if err != nil {
		panic(err)
	}
	privB, err := sr25519.GenerateKey(mRand)
	if err != nil {
		panic(err)
	}

	//fmt.Printf("A = %x\n", privA.PublicKey.MustMarshalBinary())
	//fmt.Printf("B = %x\n", privB.PublicKey.MustMarshalBinary())

	msA, err := musig2.NewMuSig2(mRand, privA, msg)
	if err != nil {
		panic(err)
	}
	msB, err := musig2.NewMuSig2(mRand, privB, msg)
	if err != nil {
		panic(err)
	}

	noncesA, err := msA.OurNonces()
	if err != nil {
		panic(err)
	}
	//fmt.Printf("noncesA: %x\n", noncesA)
	noncesB, err := msB.OurNonces()
	if err != nil {
		panic(err)
	}
	//fmt.Printf("noncesB: %x\n", noncesB)

	if err := msA.AddOtherNonces(msB.PublicKey().MustMarshalBinary(), noncesB); err != nil {
		panic(err)
	}
	if err := msB.AddOtherNonces(msA.PublicKey().MustMarshalBinary(), noncesA); err != nil {
		panic(err)
	}

	cosigA, err := msA.OurCosig()
	if err != nil {
		panic(err)
	}
	cosigB, err := msB.OurCosig()
	if err != nil {
		panic(err)
	}

	//fmt.Printf("cosigA: %x\n", cosigA)
	//fmt.Printf("cosigB: %x\n", cosigB)

	if err := msA.AddOtherCosig(msB.PublicKey().MustMarshalBinary(), cosigB); err != nil {
		panic(err)
	}
	if err := msB.AddOtherCosig(msA.PublicKey().MustMarshalBinary(), cosigA); err != nil {
		panic(err)
	}

	sigA, err := msA.Sign()
	if err != nil {
		panic(err)
	}
	sigB, err := msB.Sign()
	if err != nil {
		panic(err)
	}

	//fmt.Printf("sigA: %x\n", sigA)
	//fmt.Printf("sigB: %x\n", sigB)
	if !bytes.Equal(sigA, sigB) {
		panic("mismatch sig")
	}

	Xs := []*sr25519.PublicKey{&privA.PublicKey, &privB.PublicKey}
	if err := musig2.Verify(Xs, msg, sigA); err != nil {
		panic("verify failed")
	}

	// Output:
	//
}
