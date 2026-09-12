package field

import (
	"math/big"
	"strings"
	"testing"
)

// Elements just below the modulus are the hazard: gnark-crypto renders q-k as
// "-k" for k below 65536, which ToBig rejects. Everything this package hands
// out has to stay in canonical decimal form.
func TestEncodingStaysCanonicalNearTheModulus(t *testing.T) {
	for _, k := range []int64{1, 2, 65535, 65536, 1 << 20} {
		e := FromBig(new(big.Int).Sub(Modulus, big.NewInt(k)))
		if strings.HasPrefix(e, "-") {
			t.Fatalf("q-%d encoded as %q", k, e)
		}
		v, err := ToBig(e)
		if err != nil {
			t.Fatalf("q-%d encoded as %q: %v", k, e, err)
		}
		if want := new(big.Int).Sub(Modulus, big.NewInt(k)); v.Cmp(want) != 0 {
			t.Fatalf("q-%d round-tripped to %s", k, v)
		}
	}
}

func TestRandomIsCanonicalAndNonZero(t *testing.T) {
	for i := 0; i < 2000; i++ {
		r, err := Random()
		if err != nil {
			t.Fatal(err)
		}
		v, err := ToBig(r)
		if err != nil {
			t.Fatalf("Random returned %q: %v", r, err)
		}
		if v.Sign() == 0 {
			t.Fatal("Random returned zero")
		}
	}
}
