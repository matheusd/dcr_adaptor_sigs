package dcr_adaptor_sigs

import (
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
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
}

// Sign generates the full signature _and_ the adaptor signature for a given
// message and private key.
func Sign(privKey *secp256k1.PrivateKey, msg []byte) (*Signature, error) {

	curve := secp256k1.S256()

	// Generate a set of usable Nonces for this signature.
	rNonce, tNonce, _, rPub, tPub, rtPub, err := usableNonces()
	if err != nil {
		return nil, err
	}

	// Calculate Hash(R+T || m)
	rtmHash := calcHash(rtPub, msg)
	rtmhx := new(big.Int)
	rtmhx.Mul(rtmHash, privKey.D)

	// Calculate the Adaptor Signature s' = r - Hash(R+T || m) * x
	adaptorSig := new(big.Int)
	adaptorSig.Mul(rtmHash, privKey.D)
	adaptorSig.Sub(rNonce, adaptorSig)
	adaptorSig.Mod(adaptorSig, curve.N)

	// TODO: bounds check adaptorSig (if == 0)

	// Calculate the full signature s = s' + t
	fullSig := new(big.Int)
	fullSig.Add(adaptorSig, tNonce)
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
	}, nil
}

// RecoverSecret allows one to recover the secret nonce (the "t" secret nonce)
// after one has seen both the full and adaptor signatures.
func RecoverSecret(s, adaptorSig *big.Int) []byte {
	secret := new(big.Int)
	secret.Sub(s, adaptorSig)
	secret.Mod(secret, secp256k1.S256().N)
	return secret.Bytes()
}

// AssembleFullSig allows one to (re-)assemble the fully valid signature after
// one has seen both the adaptor signature and the secret.
func AssembleFullSig(adaptorSig *big.Int, secret []byte) *big.Int {
	secretBig := new(big.Int)
	secretBig.SetBytes(secret)

	sig := new(big.Int)
	sig.Add(adaptorSig, secretBig)
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
