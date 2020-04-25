// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package ecdh

import (
	"crypto/rand"
	"golang.org/x/crypto/curve25519"
	"io"
	"log"
)

type ecdh25519 struct{}

var curve25519Params = CurveParams{
	Name:    "Curve25519",
	BitSize: 255,
}

// X25519 creates a new ecdh.KeyExchange with
// the elliptic curve Curve25519.
func X25519() KeyExchange {
	return ecdh25519{}
}

func (ecdh25519) GenerateKey(random io.Reader) (private []byte, public []byte, err error) {
	if random == nil {
		random = rand.Reader
	}

	pri := make([]byte, 32)
	_, err = io.ReadFull(random, pri)
	if err != nil {
		return
	}

	// From https://cr.yp.to/ecdh.html
	pri[0] &= 248
	pri[31] &= 127
	pri[31] |= 64

	//curve25519.ScalarBaseMult(&pub, &pri)
	pub, err := curve25519.X25519(pri, curve25519.Basepoint)

	return pri, pub, err
}

func (ecdh25519) Params() CurveParams { return curve25519Params }

func (ecdh25519) PublicKey(private []byte) (public []byte) {
	//curve25519.ScalarBaseMult(&pub, &pri)
	pub, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}

	return pub
}

func (ecdh25519) Check([]byte) (err error) {
	return nil
}

func (ecdh25519) ComputeSecret(private []byte, peersPublic []byte) (secret []byte) {
	var err error

	//curve25519.ScalarMult(&sec, &pri, &pub)
	secret, err = curve25519.X25519(private, peersPublic)
	if err != nil {
		log.Fatal(err)
	}

	return secret
}
