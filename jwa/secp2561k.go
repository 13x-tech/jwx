//go:build jwx_secp256k1
// +build jwx_secp256k1

package jwa

// This constant is only available if compiled with jwx_secp256k1 build tag
const Secp256k1 EllipticCurveAlgorithm = "secp256k1"

func init() {
	allEllipticCurveAlgorithms[Secp256k1] = struct{}{}
}
