package musig2_test

import (
	"bytes"
	mathrand "math/rand"
	"testing"

	"github.com/sammyne/musig2"
	"github.com/sammyne/musig2/sr25519"
)

func TestVerify_Err(t *testing.T) {
	msg := []byte("hello-world")

	mRand := mathrand.New(mathrand.NewSource(123))

	privA, err := sr25519.GenerateKey(mRand)
	if err != nil {
		t.Fatal(err)
	}
	privB, err := sr25519.GenerateKey(mRand)
	if err != nil {
		t.Fatal(err)
	}

	msA, err := musig2.NewMuSig2(mRand, privA, msg)
	if err != nil {
		t.Fatal(err)
	}
	msB, err := musig2.NewMuSig2(mRand, privB, msg)
	if err != nil {
		t.Fatal(err)
	}

	noncesA, err := msA.OurNonces()
	if err != nil {
		t.Fatal(err)
	}
	noncesB, err := msB.OurNonces()
	if err != nil {
		t.Fatal(err)
	}

	if err := msA.AddOtherNonces(msB.PublicKey().MustMarshalBinary(), noncesB); err != nil {
		t.Fatal(err)
	}
	if err := msB.AddOtherNonces(msA.PublicKey().MustMarshalBinary(), noncesA); err != nil {
		t.Fatal(err)
	}

	cosigA, err := msA.OurCosig()
	if err != nil {
		t.Fatal(err)
	}
	cosigB, err := msB.OurCosig()
	if err != nil {
		t.Fatal(err)
	}

	if err := msA.AddOtherCosig(msB.PublicKey().MustMarshalBinary(), cosigB); err != nil {
		t.Fatal(err)
	}
	if err := msB.AddOtherCosig(msA.PublicKey().MustMarshalBinary(), cosigA); err != nil {
		t.Fatal(err)
	}

	sigA, err := msA.Sign()
	if err != nil {
		t.Fatal(err)
	}
	sigB, err := msB.Sign()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(sigA, sigB) {
		t.Fatal("mismatch sig")
	}

	Xs := []*sr25519.PublicKey{&privA.PublicKey, &privB.PublicKey}
	sigA[0] = ^sigA[0]
	if err := musig2.Verify(Xs, msg, sigA); err == nil {
		t.Fatal("missing error")
	}
}
