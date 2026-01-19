package jwks

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

type Key struct {
	Alg string `json:"alg"`
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`

	publicKey *rsa.PublicKey
}

func (k *Key) resolvePublicKey() error {
	if k.Kty != "RSA" {
		return fmt.Errorf("unsupported key type: %s", k.Kty)
	}

	// Decode base64url encoded modulus (n)
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return fmt.Errorf("failed to decode modulus: %w", err)
	}

	// Decode base64url encoded exponent (e)
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert exponent bytes to int
	var eInt int
	for _, b := range eBytes {
		eInt = eInt<<8 | int(b)
	}

	// Create RSA public key
	k.publicKey = &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}

	return nil
}
