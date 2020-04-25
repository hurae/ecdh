// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package ecdh

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

// Generic creates a new ecdh.KeyExchange with
// generic elliptic.Curve implementations.
func Generic(c elliptic.Curve) KeyExchange {
	if c == nil {
		panic("ecdh: curve is nil")
	}
	return genericCurve{curve: c}
}

type genericCurve struct {
	curve elliptic.Curve
}

func (g genericCurve) GenerateKey(random io.Reader) (private []byte, public []byte, err error) {
	if random == nil {
		random = rand.Reader
	}
	private, x, y, err := elliptic.GenerateKey(g.curve, random)
	if err != nil {
		private = nil
		return
	}
	public = elliptic.Marshal(g.curve, x, y)
	return
}

func (g genericCurve) Params() CurveParams {
	p := g.curve.Params()
	return CurveParams{
		Name:    p.Name,
		BitSize: p.BitSize,
	}
}

func (g genericCurve) PublicKey(private []byte) (public []byte) {
	N := g.curve.Params().N
	if new(big.Int).SetBytes(private).Cmp(N) >= 0 {
		panic("ecdh: private key cannot used with given curve")
	}
	x, y := g.curve.ScalarBaseMult(private)
	public = elliptic.Marshal(g.curve, x, y)
	return
}

func (g genericCurve) Check(peersPublic []byte) (err error) {
	x, y := elliptic.Unmarshal(g.curve, peersPublic)
	if !g.curve.IsOnCurve(x, y) {
		err = errors.New("peer's public key is not on curve")
	}
	return
}

func (g genericCurve) ComputeSecret(private []byte, peersPublic []byte) (secret []byte) {
	x, y := elliptic.Unmarshal(g.curve, peersPublic)
	sX, _ := g.curve.ScalarMult(x, y, private)
	secret = sX.Bytes()
	return
}
