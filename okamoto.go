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

// Encrypt encrypts a plain text represented as a byte array. It returns
// an error if plain text value is larger than modulus N of Public key.
func (pub *PublicKey) Encrypt(plainText []byte) ([]byte, error) {
	// choose a random integer r from {1...n-1}
	r, err := rand.Int(rand.Reader, new(big.Int).Sub(pub.N, one))
	if err != nil {
		return nil, err
	}

	m := new(big.Int).SetBytes(plainText)
	if m.Cmp(pub.N) == 1 { //  m < N
		return nil, ErrLargeMessage
	}

	// c = g^m * h^r mod N
	c := new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Exp(pub.G, m, pub.N),
			new(big.Int).Exp(pub.H, r, pub.N),
		),
		pub.N,
	)
	return c.Bytes(), nil
}

// Decrypt decrypts the passed cipher text. It returns an
// error if ciphe text value is larger than modulus N of Public key.
func (priv *PrivateKey) Decrypt(cipherText []byte) ([]byte, error) {
	c := new(big.Int).SetBytes(cipherText)
	if c.Cmp(priv.N) == 1 { // c < N
		return nil, ErrLargeCipher
	}
	pminuse1 := new(big.Int).Sub(priv.P, one)

	// c^(p-1) mod p^2
	a := new(big.Int).Exp(c, pminuse1, priv.PSquared)

	// L1(a) = (a - 1) / p
	l1 := new(big.Int).Div(
		new(big.Int).Sub(a, one),
		priv.P,
	)

	// L2(b) = (b-1) / p
	l2 := new(big.Int).Div(
		new(big.Int).Sub(priv.GD, one),
		priv.P,
	)

	// b^(-1) mod p
	binverse := new(big.Int).ModInverse(l2, priv.P)

	// m = L(a*b^(-1) mod p^2) mod p
	m := new(big.Int).Mod(
		new(big.Int).Mul(l1, binverse),
		priv.P,
	)
	return m.Bytes(), nil
}

// HomomorphicEncTwo performs homomorphic operation over two passed chiphers.
// Okamoto-Uchiyama has additive homomorphic property, so resultant cipher
// contains the sum of two numbers.
func (pub *PublicKey) HomomorphicEncTwo(c1, c2 []byte) ([]byte, error) {
	cipherA := new(big.Int).SetBytes(c1)
	cipherB := new(big.Int).SetBytes(c2)
	if cipherA.Cmp(pub.N) == 1 && cipherB.Cmp(pub.N) == 1 { // c < N
		return nil, ErrLargeCipher
	}

	// C = c1*c2 mod N
	C := new(big.Int).Mod(
		new(big.Int).Mul(cipherA, cipherB),
		pub.N,
	)
	return C.Bytes(), nil
}

// HommorphicEncMultiple performs homomorphic operation over multiple passed chiphers.
// Okamoto-Uchiyama has additive homomorphic property, so resultant cipher
// contains the sum of multiple numbers.
func (pub *PublicKey) HommorphicEncMultiple(ciphers ...[]byte) ([]byte, error) {
	C := one

	for i := 0; i < len(ciphers); i++ {
		cipher := new(big.Int).SetBytes(ciphers[i])
		if cipher.Cmp(pub.N) == 1 { // c < N
			return nil, ErrLargeCipher
		}
		// C = c1*c2*c3...cn mod N
		C = new(big.Int).Mod(
			new(big.Int).Mul(C, cipher),
			pub.N,
		)
	}
	return C.Bytes(), nil
}
