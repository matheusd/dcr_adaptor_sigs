package dcr_adaptor_sigs

import (
	"math/big"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
)

const scalarSize = 32

func b2f(b *big.Int) *secp256k1.FieldVal {
	var res secp256k1.FieldVal
	res.SetByteSlice(b.Bytes())
	return &res
}

func pubkeyFromPrivData(privData []byte) *secp256k1.PublicKey {
	pubX, pubY := secp256k1.S256().ScalarBaseMult(privData)
	return secp256k1.NewPublicKey(b2f(pubX), b2f(pubY))
}

func addPubKeys(p1, p2 *secp256k1.PublicKey) *secp256k1.PublicKey {
	r1, r2 := secp256k1.S256().Add(p1.X(), p1.Y(), p2.X(), p2.Y())
	return secp256k1.NewPublicKey(b2f(r1), b2f(r2))
}

func pubKeyMult(p *secp256k1.PublicKey, k []byte) *secp256k1.PublicKey {
	x, y := secp256k1.S256().ScalarMult(p.X(), p.Y(), k)
	return secp256k1.NewPublicKey(b2f(x), b2f(y))
}

// bigIntToEncodedBytes converts a big integer into its corresponding 32 byte
// little endian representation.
func bigIntToEncodedBytes(a *big.Int) *[32]byte {
	s := new([32]byte)
	if a == nil {
		return s

	}
	// Caveat: a can be longer than 32 bytes.
	aB := a.Bytes()

	// If we have a short byte string,
	// expand it so that it's long enough.
	aBLen := len(aB)
	if aBLen < scalarSize {
		diff := scalarSize - aBLen
		for i := 0; i < diff; i++ {
			aB = append([]byte{0x00}, aB...)

		}

	}

	for i := 0; i < scalarSize; i++ {
		s[i] = aB[i]

	}

	return s

}

// encodedBytesToBigInt converts a 32 byte big endian representation of an
// integer into a big integer.
func encodedBytesToBigInt(s []byte) *big.Int {
	// Use a copy so we don't screw up our original
	// memory.
	var c [32]byte
	copy(c[:], s[:])
	bi := new(big.Int).SetBytes(c[:])
	return bi
}

func calcHash(pub *secp256k1.PublicKey, msg []byte) *big.Int {
	pubBytes := bigIntToEncodedBytes(pub.X())
	var input [64]byte
	copy(input[:32], pubBytes[:])
	copy(input[32:], msg[:])
	output := chainhash.HashB(input[:])
	outputBig := new(big.Int).SetBytes(output)
	return outputBig
}

// produceR generates the R = T+U full nonce. It returns true on the second
// return value if the point needed to be inverted to maintain consistency with
// current consensus rules.
func produceR(uPub, tPub *secp256k1.PublicKey) (*secp256k1.PublicKey, bool) {
	inverted := false
	rPub := addPubKeys(uPub, tPub)
	if rPub.Y().Bit(0) == 1 {
		inverted = true
		newX := new(big.Int).Sub(rPub.X(), secp256k1.S256().N)
		newX.Mod(newX, secp256k1.S256().N)
		var newY secp256k1.FieldVal
		if !secp256k1.DecompressY(b2f(newX), false, &newY) {
			// This shouldn't happen as long as the input pubkeys
			// are valid.
			panic("bogus R after inversion!")
		}
		rPub = secp256k1.NewPublicKey(b2f(newX), &newY)
	}

	return rPub, inverted
}

// FullSigR produces the R point for the fully valid Schnorr sig starting from
// the public nonce (uPub) and the point corresponding to the target secret
// scalar (tPub).
func FullSigR(uPub, tPub *secp256k1.PublicKey) *secp256k1.PublicKey {
	r, _ := produceR(uPub, tPub)
	return r
}
