package dcr_adaptor_sigs

import (
	"crypto/rand"
	"math/big"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v2"
)

const scalarSize = 32

func pubkeyFromPrivData(privData []byte) *secp256k1.PublicKey {
	pubX, pubY := secp256k1.S256().ScalarBaseMult(privData)
	return secp256k1.NewPublicKey(pubX, pubY)
}

func addPubKeys(p1, p2 *secp256k1.PublicKey) *secp256k1.PublicKey {
	r1, r2 := secp256k1.S256().Add(p1.X, p1.Y, p2.X, p2.Y)
	return secp256k1.NewPublicKey(r1, r2)
}

func pubKeyMult(p *secp256k1.PublicKey, k []byte) *secp256k1.PublicKey {
	x, y := secp256k1.S256().ScalarMult(p.X, p.Y, k)
	return secp256k1.NewPublicKey(x, y)
}

func negatePubKey(p *secp256k1.PublicKey) *secp256k1.PublicKey {
	newy := new(big.Int)
	newy.Add(p.X, p.Y)
	newy.Mod(newy, secp256k1.S256().N)
	return secp256k1.NewPublicKey(p.X, newy)
}

// usableNonces returns the usable r,r,r+t secret and public nonces for use
// with and adaptor signature.
func usableNonces() (*big.Int, *big.Int, *big.Int, *secp256k1.PublicKey, *secp256k1.PublicKey, *secp256k1.PublicKey, error) {
	var buf [32]byte

	rNonce := new(big.Int)
	tNonce := new(big.Int)

	for {
		_, err := rand.Read(buf[:])
		if err != nil {
			return nil, nil, nil, nil, nil, nil, err
		}

		rNonce.SetBytes(buf[:])

		_, err = rand.Read(buf[:])
		if err != nil {
			return nil, nil, nil, nil, nil, nil, err
		}

		tNonce.SetBytes(buf[:])

		rPub := pubkeyFromPrivData(rNonce.Bytes())
		tPub := pubkeyFromPrivData(tNonce.Bytes())
		rtPub := addPubKeys(rPub, tPub)

		// TODO: bounds check rNonce, tNonce, rtNonce, rPub, tPub,
		// rtPub.

		// Due to how schnorr sig is currently verified, only nonces
		// whose corresponding pubkey's Y value is even can be used, so
		// regenerate until we get a set that matches. This could be
		// improved... :(
		//
		// Ideally we should be using compact representation for
		// pubkeys/nonces/signatures so that arbitrary nonces could be
		// used.
		if tPub.Y.Bit(0) == 1 || rtPub.Y.Bit(0) == 1 {
			continue
		}

		rtNonce := new(big.Int)
		rtNonce.Add(rNonce, tNonce)
		rtNonce.Mod(rtNonce, secp256k1.S256().N)

		return rNonce, tNonce, rtNonce, rPub, tPub, rtPub, nil
	}
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

func calcHash(pub *secp256k1.PublicKey, msg []byte) *big.Int {
	pubBytes := bigIntToEncodedBytes(pub.X)
	var input [64]byte
	copy(input[:32], pubBytes[:])
	copy(input[32:], msg[:])
	output := chainhash.HashB(input[:])
	outputBig := new(big.Int).SetBytes(output)
	return outputBig
}
