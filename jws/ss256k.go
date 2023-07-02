//go:build jwx_secp256k1
// +build jwx_secp256k1

package jws

import (
	"github.com/lestrrat-go/jwx/v2/jwa"
)

func init() {
	addAlgorithmForKeyType(jwa.EC, jwa.SS256K)
}
