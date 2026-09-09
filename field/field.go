// Package field holds the finite-field helpers shared by the protocol layer
// and the ZK circuit. Every circuit-bound value is an element of the BN254
// scalar field, carried as a decimal string so that protocol messages stay
// JSON-friendly and match the JavaScript reference implementation.
package field

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

// Modulus is the BN254 scalar field modulus.
var Modulus = fr.Modulus()

// Element is a field element in canonical decimal form.
type Element = string

// ErrInvalidElement is returned when a string is not a canonical element.
var ErrInvalidElement = errors.New("field: invalid element")

// ToBig parses a canonical element.
func ToBig(e Element) (*big.Int, error) {
	v, ok := new(big.Int).SetString(e, 10)
	if !ok || v.Sign() < 0 || v.Cmp(Modulus) >= 0 {
		return nil, fmt.Errorf("%w: %q", ErrInvalidElement, e)
	}
	return v, nil
}

// FromBig reduces an integer into the field.
func FromBig(v *big.Int) Element {
	return new(big.Int).Mod(v, Modulus).String()
}

// FromInt reduces a machine integer into the field.
func FromInt(v int64) Element {
	return FromBig(big.NewInt(v))
}

// Random returns a uniformly random non-zero element.
func Random() (Element, error) {
	for {
		var e fr.Element
		if _, err := e.SetRandom(); err != nil {
			return "", fmt.Errorf("field: random element: %w", err)
		}
		if !e.IsZero() {
			return e.String(), nil
		}
	}
}

// FromText maps an application-level identifier into the field. Human-readable
// names stay at the application boundary; only their digests enter the circuit.
func FromText(text string) Element {
	digest := sha256.Sum256([]byte(text))
	return FromBig(new(big.Int).SetBytes(digest[:]))
}

// Hash is the Poseidon2 hash over field elements. It matches the in-circuit
// Poseidon2 gadget from gnark when the same elements are absorbed in order.
func Hash(fields ...Element) (Element, error) {
	h := poseidon2.NewMerkleDamgardHasher()
	for _, f := range fields {
		v, err := ToBig(f)
		if err != nil {
			return "", err
		}
		var e fr.Element
		e.SetBigInt(v)
		b := e.Bytes()
		if _, err := h.Write(b[:]); err != nil {
			return "", fmt.Errorf("field: hash: %w", err)
		}
	}
	return FromBig(new(big.Int).SetBytes(h.Sum(nil))), nil
}

// Commit is a hiding commitment Commit(value, salt) = Hash(value, salt).
func Commit(value, salt Element) (Element, error) {
	return Hash(value, salt)
}

// Bytes returns the 32-byte big-endian encoding of an element. It is the
// message format used when signing field elements.
func Bytes(e Element) ([]byte, error) {
	v, err := ToBig(e)
	if err != nil {
		return nil, err
	}
	var el fr.Element
	el.SetBigInt(v)
	b := el.Bytes()
	return b[:], nil
}

// Add returns a + b in the field.
func Add(a, b Element) (Element, error) {
	x, err := ToBig(a)
	if err != nil {
		return "", err
	}
	y, err := ToBig(b)
	if err != nil {
		return "", err
	}
	return FromBig(new(big.Int).Add(x, y)), nil
}

// Sub returns a - b in the field.
func Sub(a, b Element) (Element, error) {
	x, err := ToBig(a)
	if err != nil {
		return "", err
	}
	y, err := ToBig(b)
	if err != nil {
		return "", err
	}
	return FromBig(new(big.Int).Sub(x, y)), nil
}

// Less reports whether a < b as integers.
func Less(a, b Element) (bool, error) {
	x, err := ToBig(a)
	if err != nil {
		return false, err
	}
	y, err := ToBig(b)
	if err != nil {
		return false, err
	}
	return x.Cmp(y) < 0, nil
}
