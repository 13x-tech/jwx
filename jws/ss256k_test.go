//go:build jwx_secp256k1
// +build jwx_secp256k1

package jws_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
)

func init() {
	hasSS256K = true
}

func TestSS256K(t *testing.T) {
	payload := []byte("Hello, World!")

	t.Parallel()
	key, err := jwxtest.GenerateSchnorrKey()
	if !assert.NoError(t, err, "ECDSA key generated") {
		return
	}
	jwkKey, _ := jwk.FromRaw(key.PubKey())
	keys := map[string]interface{}{
		"Verify(secp256k1.PublicKey)":  *key.PubKey(),
		"Verify(*secp256k1.PublicKey)": key.PubKey(),
		"Verify(jwk.Key)":              jwkKey,
	}
	testRoundtrip(t, payload, jwa.ES256K, key, keys)
}
