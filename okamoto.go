package okamotoUchiyama

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

var one = big.NewInt(1)
var ErrLargeMessage = errors.New("okamoto-uchiyama: message is larger than Schmidt Samoa public key size")
var ErrLargeCipher = errors.New("okamoto-uchiyama: message is larger than Schmidt Samoa public key size")

// PrivateKey represents a Okamoto-Uchiyama private key.
type PrivateKey struct {
	PublicKey
	GD       *big.Int
	P        *big.Int
	PSquared *big.Int
}

// PublicKey represents Okamoto-Uchiyama public key.
type PublicKey struct {
	N *big.Int
	G *big.Int
	H *big.Int
}

// GenerateKey generats the private key of the Okamoto-Uchiyama cryptosystem.
func GenerateKey(random io.Reader, bits int) (*PrivateKey, error) {
	// prime number p
	p, err := rand.Prime(random, bits/2)
	if err != nil {
		return nil, err
	}

	// prime number q
	q, err := rand.Prime(random, bits/2)
	if err != nil {
		return nil, err
	}

	// psquare = p * p
	psquare := new(big.Int).Mul(p, p)
	// n = psquare * q
	n := new(big.Int).Mul(psquare, q)

	// randomly choosing ineger g from {2...n-1},
	// such that g^(p-1) mod p^2 != 1
	var g, gpminuse1 *big.Int
	for {
		pminuse1 := new(big.Int).Sub(p, one)
		g, err = rand.Int(rand.Reader, new(big.Int).Sub(n, one))
		if err != nil {
			return nil, err
		}

		gpminuse1 = new(big.Int).Mod(
			new(big.Int).Exp(g, pminuse1, psquare),
			psquare,
		)

		if gpminuse1.Cmp(one) != 0 {
			break
		}
	}

	// h = g^n mod n
	h := new(big.Int).Mod(
		new(big.Int).Exp(g, n, n),
		n,
	)
	return &PrivateKey{
		PublicKey: PublicKey{
			N: n,
			G: g,
			H: h,
		},
		GD:       gpminuse1,
		P:        p,
		PSquared: psquare,
	}, nil
}
