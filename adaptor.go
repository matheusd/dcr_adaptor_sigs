package dcr_adaptor_sigs

import (
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
)

const (
	// negativeSecretFlag is the bit that indicates the secret is encoded
	// as a negative number in adaptor signatures and should be
	// appropriately handled.
	negativeSecretFlag = 0x01
)

// Signature is the full signature + adaptor signature data.
//
// TODO: Maybe Signature should only be R,S and we should create a
// AdaptorSignature struct.
type Signature struct {
	// These are the fields of the fully valid signature.

	R *big.Int // R = rG + tG
	S *big.Int // s = r + t - Hash(R+T || m) * privKey

	// These are the fields of the adaptor signature.

	TNonce     *secp256k1.PublicKey // T = secret * G
	RNonce     *secp256k1.PublicKey // R = rG
	AdaptorSig *big.Int             // s' = r + Hash(R+T || m) * privKey
	Secret     []byte               // secret = s - s'
	Flags      byte
}

// Noncer defines a single function Nonces that is used to generate nonces for
// adaptor signatures.
type Noncer interface {
	// Nonces should return the `r` and `t` nonce data (respectively)
	// required to generate nonces for the signing operation. The `t` nonce
	// data is the secret preimage revealed by the difference between the
	// adaptor signature and the full signature.
	//
	// WARNING: reusing or otherwise generating deterministic nonces
	// discloses the private signing key, therefore the returned bytes
	// should ideally be generated from a cryptographically secure random
	// number generator.
	Nonces() ([]byte, []byte, error)
}

// Sign generates the full signature _and_ the adaptor signature for a given
// message and private key.
func Sign(privKey *secp256k1.PrivateKey, msg []byte, noncer Noncer) (*Signature, error) {

	curve := secp256k1.S256()
	var flags byte

	// Generate the nonces.
	rNonceData, tNonceData, err := noncer.Nonces()
	if err != nil {
		return nil, err
	}

	// TODO: bounds check them.

	// Find out the corresponding pub keys for the nonces.
	rNonce := encodedBytesToBigInt(rNonceData)
	tNonce := encodedBytesToBigInt(tNonceData)
	rPub := pubkeyFromPrivData(rNonce.Bytes())
	tPub := pubkeyFromPrivData(tNonce.Bytes())

	// rtNonce = r+t
	rtNonce := new(big.Int)
	rtNonce.Add(rNonce, tNonce)
	rtNonce.Mod(rtNonce, curve.N)
	rtPub := pubkeyFromPrivData(rtNonce.Bytes())

	// Maintain R+T in group order as required by consensus rules for
	// schnorr verification. In that case, send out a flag that indicates
	// the secret is "negative" and we need to perform a slightly different
	// operation to extract it from the full and adaptor signatures.
	if rtPub.Y.Bit(0) == 1 {
		rtNonce.Sub(curve.N, rtNonce)
		rtPub = pubkeyFromPrivData(rtNonce.Bytes())
		flags = flags | negativeSecretFlag
	}

	// Calculate Hash(R+T || m)
	rtmHash := calcHash(rtPub, msg)
	rtmhx := new(big.Int)
	rtmhx.Mul(rtmHash, privKey.D)

	// Calculate the Adaptor Signature s' = r - Hash(R+T || m) * x
	adaptorSig := new(big.Int)
	if flags&negativeSecretFlag > 0 {
		adaptorSig.Sub(curve.N, rNonce)
		adaptorSig.Sub(adaptorSig, rtmhx)
	} else {
		adaptorSig.Sub(rNonce, rtmhx)
	}
	adaptorSig.Mod(adaptorSig, curve.N)

	// TODO: bounds check adaptorSig (if == 0)

	// Calculate the full signature s = s' + t
	fullSig := new(big.Int)
	fullSig.Sub(rtNonce, rtmhx)
	fullSig.Mod(fullSig, curve.N)

	// TODO: bounds check fullSig (if == 0)

	// Done! Return all data.
	return &Signature{
		R: rtPub.X,
		S: fullSig,

		TNonce:     tPub,
		RNonce:     rPub,
		AdaptorSig: adaptorSig,
		Secret:     tNonce.Bytes(),
		Flags:      flags,
	}, nil
}

// RecoverSecret allows one to recover the secret nonce (the "t" secret nonce)
// after one has seen both the full and adaptor signatures.
func RecoverSecret(s, adaptorSig *big.Int, flags byte) []byte {
	secret := new(big.Int)
	if flags&negativeSecretFlag > 0 {
		secret.Sub(adaptorSig, s)
	} else {
		secret.Sub(s, adaptorSig)
	}
	secret.Mod(secret, secp256k1.S256().N)
	return secret.Bytes()
}

// AssembleFullSig allows one to (re-)assemble the fully valid signature after
// one has seen both the adaptor signature and the secret.
func AssembleFullSig(adaptorSig *big.Int, secret []byte, flags byte) *big.Int {
	secretBig := new(big.Int)
	secretBig.SetBytes(secret)

	sig := new(big.Int)
	if flags&negativeSecretFlag > 0 {
		sig.Sub(adaptorSig, secretBig)
	} else {
		sig.Add(adaptorSig, secretBig)
	}
	sig.Mod(sig, secp256k1.S256().N)
	return sig
}

// VerifyAdaptorSig allows one to verify whether a given adaptor sig is valid,
// given the corresponding `rtPubX` (i.e., the R of a fully valid signature),
// pubkey and R public nonce.
func VerifyAdaptorSig(rtPubX *big.Int, r, pubKey *secp256k1.PublicKey, adaptorSig *big.Int, msg []byte) bool {

	// The verification equation is:
	//
	//     s'G ?= R - H(R+T || m)*P
	//
	// Rewriting we get:
	//
	//    s'G + H(R+T || m)*P ?= R

	// Calculate Hash(R+T || m).
	bigZero := new(big.Int)
	rtPub := secp256k1.NewPublicKey(rtPubX, bigZero)
	rtmHash := calcHash(rtPub, msg)

	// Multiply by the pubkey to get E = Hash(R+T ||m) * P.
	rtmHashBytes := rtmHash.Bytes()
	hpub := pubKeyMult(pubKey, rtmHashBytes[:])

	// We want to verify whether s'G + E == R , so calculate s'G.
	sBytes := adaptorSig.Bytes()
	sg := pubkeyFromPrivData(sBytes[:])

	// Add everything to get s'G + Hash(R+T || m) * P.
	targetPoint := addPubKeys(sg, hpub)

	// That must equal the partial nonce R = rG
	return r.X.Cmp(targetPoint.X) == 0
}
