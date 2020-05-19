[![Godoc Reference](https://godoc.org/github.com/hurae/ecdh?status.svg)](https://godoc.org/github.com/hurae/ecdh)

Fork of `github.com/aead/ecdh`

## The ECDH key exchange

## Elliptic curve Diffie–Hellman (ECDH) is an anonymous key agreement protocol that allows two parties, 

each having an elliptic curve public–private key pair, to establish a shared secret over an insecure channel.  

This package implements a generic interface for ECDH and supports the generic [crypto/elliptic](https://godoc.org/crypto/elliptic)
and the [x/crypto/curve25519](https://godoc.org/golang.org/x/crypto/curve25519) out of the box.

### Installation

Install in your GOPATH: `go get -u github.com/hurae/ecdh`  

### Difference:

- always return a []byte type public key
- use non-deprecated new X25519 API.
- implement Check for Curve25519, just the same check inside golang.org/x/crypto/curve25519. That means length 32 and not all zero.
- ComputeSecret will now pass the error which golang.org/x/crypto/curve25519 gives out.