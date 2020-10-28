package sr25519

import (
	"crypto/rand"
	"testing"

	"github.com/gtank/ristretto255"
)

func Test_ScalarMul(t *testing.T) {
	x, err := randScalar(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	y, err := randScalar(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	z := ristretto255.NewScalar().Multiply(x, y)

	// clone x
	zz := ristretto255.NewScalar()
	if err := zz.Decode(x.Encode(nil)); err != nil {
		t.Fatal(err)
	}

	zz.Multiply(zz, y)

	if z.Equal(zz) != 1 {
		t.Fatalf("in-place mul failed: expect %s, got %s", z, zz)
	}
}
