package jws

import (
	"crypto"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
	"github.com/lestrrat-go/jwx/v2/internal/keyconv"
	"github.com/lestrrat-go/jwx/v2/jwa"
)

func newSchnorrSigner(alg jwa.SignatureAlgorithm) Signer {
	return schnorrSigners[alg]
}

type schnorrSigner struct {
	alg  jwa.SignatureAlgorithm
	hash crypto.Hash
}

func (s schnorrSigner) Algorithm() jwa.SignatureAlgorithm {
	return s.alg
}

func (s *schnorrSigner) Sign(payload []byte, key interface{}) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf(`missing private key while signing payload`)
	}

	h := s.hash.New()
	if _, err := h.Write(payload); err != nil {
		return nil, fmt.Errorf(`failed to write payload using ecdsa: %w`, err)
	}
	var privkey secp256k1.PrivateKey
	if err := keyconv.SchnorrPrivateKEy(&privkey, key); err != nil {
		return nil, fmt.Errorf(`failed to retrieve secp256k1.PrivateKey out of %T: %w`, key, err)
	}

	sig, err := schnorr.Sign(&privkey, h.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf(`failed to sign using schnorr: %w`, err)
	}

	return sig.Serialize(), nil
}

func newSchnorrVerifier(alg jwa.SignatureAlgorithm) Verifier {
	return schnorrVerifiers[alg]
}

// schnorrVerifiers are immutable.
type schnorrVerifier struct {
	alg  jwa.SignatureAlgorithm
	hash crypto.Hash
}

func (v schnorrVerifier) Algorithm() jwa.SignatureAlgorithm {
	return v.alg
}

func (v *schnorrVerifier) Verify(payload []byte, signature []byte, key interface{}) error {
	if key == nil {
		return fmt.Errorf(`missing public key while verifying payload`)
	}

	var pubkey secp256k1.PublicKey
	if cs, ok := key.(crypto.Signer); ok {
		cpub := cs.Public()
		switch cpub := cpub.(type) {
		case secp256k1.PublicKey:
			pubkey = cpub
		case *secp256k1.PublicKey:
			pubkey = *cpub
		default:
			return fmt.Errorf(`failed to retrieve secp256k1.PublicKey out of crypto.Signer %T`, key)
		}
	} else {
		if err := keyconv.SchnorrPublicKey(&pubkey, key); err != nil {
			return fmt.Errorf(`failed to retrieve secp256k1.PublicKey out of %T: %w`, key, err)
		}
	}

	if !pubkey.IsOnCurve() {
		return fmt.Errorf(`public key used does not contain a point (X,Y) on the curve`)
	}

	sig, err := schnorr.ParseSignature(signature)
	if err != nil {
		return fmt.Errorf(`failed to parse schnorr signature bytes: %w`, err)
	}

	h := v.hash.New()
	if _, err := h.Write(payload); err != nil {
		return fmt.Errorf(`failed to write payload using ecdsa: %w`, err)
	}
	if !sig.Verify(h.Sum(nil), &pubkey) {
		return fmt.Errorf(`failed to verify signature using schnorr`)
	}

	return nil
}
