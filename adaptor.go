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

type SecretScalar [32]byte

// Signature is the fully valid Schnorr signature.
type Signature struct {
	R *secp256k1.PublicKey // R = tG + uG
	S *big.Int             // s = t + u - Hash(T+U || m) * privKey
}

// AdaptorSignature is the partial adaptor signature.
type AdaptorSignature struct {
	T      *secp256k1.PublicKey // T = secret * G
	U      *secp256k1.PublicKey // U = uG
	R      *secp256k1.PublicKey // R = T + U
	SPrime *big.Int             // s' = u + Hash(T+U || m) * privKey
	Flags  byte
}

// Noncer defines a single function Nonces that is used to generate nonces for
// adaptor signatures.
type Noncer interface {
	// Nonces should return the `t`, and `u` nonce data (respectively)
	// required to generate nonces for the signing operation. The `t` nonce
	// data is the secret preimage revealed by the difference between the
	// adaptor signature and the full signature.
	//
	// WARNING: reusing or otherwise generating deterministic nonces
	// discloses the private signing key, therefore the returned bytes
	// should ideally be generated from a cryptographically secure random
	// number generator.
	Nonces() (SecretScalar, [32]byte, error)
}

// Sign generates the full signature _and_ the adaptor signature for a given
// message and private key.
func Sign(privKey *secp256k1.PrivateKey, msg []byte, noncer Noncer) (*Signature, *AdaptorSignature, error) {

	curve := secp256k1.S256()
	var flags byte

	// Generate the nonces.
	tNonceData, uNonceData, err := noncer.Nonces()
	if err != nil {
		return nil, nil, err
	}

	// TODO: bounds check them.

	// Find out the corresponding pub keys for the nonces.
	tNonce := encodedBytesToBigInt(tNonceData[:])
	uNonce := encodedBytesToBigInt(uNonceData[:])
	tPub := pubkeyFromPrivData(tNonce.Bytes())
	uPub := pubkeyFromPrivData(uNonce.Bytes())

	// rNonce = u+t
	rNonce := new(big.Int)
	rNonce.Add(uNonce, tNonce)
	rNonce.Mod(rNonce, curve.N)
	rPub := pubkeyFromPrivData(rNonce.Bytes())

	// Maintain R in group order as required by consensus rules for schnorr
	// verification. In that case, send out a flag that indicates the
	// secret is "negative" and we need to perform a slightly different
	// operation to extract it from the full and adaptor signatures.
	if rPub.Y.Bit(0) == 1 {
		rNonce.Sub(curve.N, rNonce)
		rPub = pubkeyFromPrivData(rNonce.Bytes())
		flags = flags | negativeSecretFlag
	}

	// Calculate Hash(T+U || m) * x
	rmHash := calcHash(rPub, msg)
	rmhx := new(big.Int)
	rmhx.Mul(rmHash, privKey.D)

	// Calculate the Adaptor Signature s' = u - Hash(T+U || m) * x
	sPrime := new(big.Int)
	if flags&negativeSecretFlag > 0 {
		sPrime.Sub(curve.N, uNonce)
		sPrime.Sub(sPrime, rmhx)
	} else {
		sPrime.Sub(uNonce, rmhx)
	}
	sPrime.Mod(sPrime, curve.N)

	// TODO: bounds check adaptorSig (if == 0)

	// Calculate the full signature s = s' + t
	fullSig := new(big.Int)
	fullSig.Sub(rNonce, rmhx)
	fullSig.Mod(fullSig, curve.N)

	// TODO: bounds check fullSig (if == 0)

	sig := &Signature{
		R: rPub,
		S: fullSig,
	}
	adaptor := &AdaptorSignature{
		T:      tPub,
		U:      uPub,
		R:      rPub,
		SPrime: sPrime,
		Flags:  flags,
	}

	// Done! Return all data.
	return sig, adaptor, nil
}

// RecoverSecret allows one to recover the secret nonce (the "t" secret nonce)
// after one has seen both the full and adaptor signatures.
func RecoverSecret(sig *Signature, adaptor *AdaptorSignature) SecretScalar {
	secret := new(big.Int)
	if adaptor.Flags&negativeSecretFlag > 0 {
		secret.Sub(adaptor.SPrime, sig.S)
	} else {
		secret.Sub(sig.S, adaptor.SPrime)
	}
	secret.Mod(secret, secp256k1.S256().N)
	var s SecretScalar
	copy(s[:], secret.Bytes())
	return s
}

// AssembleFullSig allows one to (re-)assemble the fully valid signature after
// one has seen both the adaptor signature and the secret.
func AssembleFullSig(adaptor *AdaptorSignature, secret *SecretScalar) (*Signature, error) {
	secretBig := new(big.Int)
	secretBig.SetBytes(secret[:])

	s := new(big.Int)
	if adaptor.Flags&negativeSecretFlag > 0 {
		s.Sub(adaptor.SPrime, secretBig)
	} else {
		s.Add(adaptor.SPrime, secretBig)
	}
	s.Mod(s, secp256k1.S256().N)
	return &Signature{
		R: adaptor.R,
		S: s,
	}, nil
}

// VerifyAdaptorSig allows one to verify whether a given adaptor sig is valid,
// given the corresponding `rtPubX` (i.e., the R of a fully valid signature),
// pubkey and R public nonce.
func VerifyAdaptorSig(adaptor *AdaptorSignature, pubKey *secp256k1.PublicKey, msg []byte) bool {

	// The verification equation is:
	//
	//     s'G ?= U - H(T+U || m)*P
	//
	// Rewriting we get:
	//
	//    s'G + H(T+U || m)*P ?= U
	//
	// Recall that R = T + U

	// Calculate Hash(T+U || m).
	bigZero := new(big.Int)
	rPub := secp256k1.NewPublicKey(adaptor.R.X, bigZero)
	rmHash := calcHash(rPub, msg)

	// Multiply by the pubkey to get E = Hash(T+U ||m) * P.
	rmHashBytes := rmHash.Bytes()
	hpub := pubKeyMult(pubKey, rmHashBytes[:])

	// We want to verify whether s'G + E == U , so calculate s'G.
	sBytes := adaptor.SPrime.Bytes()
	sg := pubkeyFromPrivData(sBytes[:])

	// Add everything to get s'G + Hash(T+U || m) * P.
	targetPoint := addPubKeys(sg, hpub)

	// That must equal the partial nonce U = uG
	return adaptor.U.X.Cmp(targetPoint.X) == 0
}
