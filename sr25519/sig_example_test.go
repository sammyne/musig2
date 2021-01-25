package sr25519_test

import (
	"crypto/rand"
	"fmt"

	"github.com/sammyne/merlin"

	"github.com/sammyne/musig2/sr25519"
)

func ExampleSign() {
	priv, err := sr25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("fail to generate private key: %v", err))
	}

	const msg = "hello world"

	sig, err := sr25519.Sign(rand.Reader, priv, []byte(msg))
	if err != nil {
		panic(fmt.Sprintf("fail to sign msg: %v", err))
	}

	if !sr25519.Verify(&priv.PublicKey, []byte(msg), sig) {
		panic("fail to verify sig")
	}

	// Output:
	//
}

func ExampleMerlinSign() {
	priv, err := sr25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("fail to generate private key: %v", err))
	}

	const msg = "hello world"

	sig, err := sr25519.MerlinSign(rand.Reader, priv, newTranscript(msg))
	if err != nil {
		panic(fmt.Sprintf("fail to sign transcript: %v", err))
	}

	if !sr25519.MerlinVerify(&priv.PublicKey, newTranscript(msg), sig) {
		panic("fail to verify sig")
	}

	// Output:
	//
}

func newTranscript(msg string) *merlin.Transcript {
	transcript := merlin.NewTranscript([]byte("signing-context"))
	transcript.AppendMessage(nil, []byte(msg))
	return transcript
}
