package dcr_adaptor_sigs

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v2/schnorr"
)

type SecretScalar [32]byte

// Signature is the fully valid Schnorr signature.
type Signature struct {
	r *secp256k1.PublicKey // R = tG + uG
	s *big.Int             // s = t + u - Hash(T+U || m) * privKey
}

func (sig *Signature) SchnorrSig() *schnorr.Signature {
	return schnorr.NewSignature(sig.r.X, sig.s)
}

// AdaptorSignature is the partial adaptor signature.
type AdaptorSignature struct {
	t      *secp256k1.PublicKey // T = secret * G
	u      *secp256k1.PublicKey // U = uG
	sPrime *big.Int             // s' = u + Hash(T+U || m) * privKey
}

func (asig *AdaptorSignature) R() *secp256k1.PublicKey {
	r, _ := produceR(asig.t, asig.u)
	return r
}

// Noncer defines a single function Nonces that is used to generate nonces for
// adaptor signatures.
type Noncer interface {
	nonce(privKey *secp256k1.PrivateKey, msg []byte) [32]byte
}

type RandomNoncer struct{}

func (r RandomNoncer) nonce(_ *secp256k1.PrivateKey, _ []byte) [32]byte {
	var u [32]byte
	n, err := rand.Read(u[:])

	// Entropy failures are critical.
	if n != 32 {
		panic(fmt.Sprintf("entropy failure: only read %d random byes", n))
	}
	if err != nil {
		panic(fmt.Sprintf("entropy failure: %v", err))
	}

	return u
}

type RFC6979Noncer struct{}

func (r RFC6979Noncer) nonce(priv *secp256k1.PrivateKey, msg []byte) [32]byte {
	b := secp256k1.NonceRFC6979(priv.D, msg, nil, nil)
	var u [32]byte
	copy(u[:], b.Bytes())
	return u
}

var DefaultNoncer RFC6979Noncer

// adaptorSign produces an adaptor signature without knowledge of the private
// scalar `t`. It returns the newly created adaptor signature plus the public
// R=(T+U) and a bool indicating whether R was inverted to maintain consensus
// rules.
func adaptorSign(privKey *secp256k1.PrivateKey, msg []byte, T *secp256k1.PublicKey, u *[32]byte) (*AdaptorSignature, *secp256k1.PublicKey, bool) {
	curve := secp256k1.S256()

	uNonce := encodedBytesToBigInt(u[:])
	U := pubkeyFromPrivData(uNonce.Bytes())

	// TODO: bounds check stuff.

	// Maintain R in group order as required by consensus rules for schnorr
	// verification.
	R, inverted := produceR(T, U)

	// Calculate Hash(T+U || m) * x
	rmHash := calcHash(R, msg)
	rmhx := new(big.Int)
	rmhx.Mul(rmHash, privKey.D)

	// Calculate the Adaptor Signature s' = u - Hash(T+U || m) * x
	sPrime := new(big.Int)
	if inverted {
		sPrime.Sub(curve.N, uNonce)
		sPrime.Sub(sPrime, rmhx)
	} else {
		sPrime.Sub(uNonce, rmhx)
	}
	sPrime.Mod(sPrime, curve.N)

	// TODO: bounds check adaptorSig (if == 0)

	adaptor := &AdaptorSignature{
		t:      T,
		u:      U,
		sPrime: sPrime,
	}
	return adaptor, R, inverted
}

// AdaptorSign produces an adaptor (partial) signature for the given data.
func AdaptorSign(privKey *secp256k1.PrivateKey, msg []byte, T *secp256k1.PublicKey, noncer Noncer) (*AdaptorSignature, error) {
	u := noncer.nonce(privKey, msg)
	sig, _, _ := adaptorSign(privKey, msg, T, &u)
	return sig, nil
}

// assembleFullSig assembles the full signature given some adaptor sig and the
// secret scalar.
func assembleFullSig(adaptor *AdaptorSignature, secret *SecretScalar,
	R *secp256k1.PublicKey, inverted bool) (*Signature, error) {

	secretBig := new(big.Int)
	secretBig.SetBytes(secret[:])

	s := new(big.Int)
	if inverted {
		s.Sub(adaptor.sPrime, secretBig)
	} else {
		s.Add(adaptor.sPrime, secretBig)
	}
	s.Mod(s, secp256k1.S256().N)
	return &Signature{
		r: R,
		s: s,
	}, nil
}

// AssembleFullSig allows one to (re-)assemble the fully valid signature after
// one has seen both the adaptor signature and the secret.
func AssembleFullSig(adaptor *AdaptorSignature, secret *SecretScalar) (*Signature, error) {
	R, inverted := produceR(adaptor.u, adaptor.t)
	return assembleFullSig(adaptor, secret, R, inverted)
}

// RecoverSecret allows one to recover the secret nonce (the "t" secret nonce)
// after one has seen both the full and adaptor signatures.
func RecoverSecret(sig *Signature, adaptor *AdaptorSignature) SecretScalar {
	secret := new(big.Int)
	_, inverted := produceR(adaptor.u, adaptor.t)
	if inverted {
		secret.Sub(adaptor.sPrime, sig.s)
	} else {
		secret.Sub(sig.s, adaptor.sPrime)
	}
	secret.Mod(secret, secp256k1.S256().N)
	var s SecretScalar
	copy(s[:], secret.Bytes())
	return s
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
	rPub, _ := produceR(adaptor.t, adaptor.u)
	rmHash := calcHash(rPub, msg)

	// Multiply by the pubkey to get E = Hash(T+U ||m) * P.
	rmHashBytes := rmHash.Bytes()
	hpub := pubKeyMult(pubKey, rmHashBytes[:])

	// We want to verify whether s'G + E == U , so calculate s'G.
	sBytes := adaptor.sPrime.Bytes()
	sg := pubkeyFromPrivData(sBytes[:])

	// Add everything to get s'G + Hash(T+U || m) * P.
	targetPoint := addPubKeys(sg, hpub)

	// That must equal the partial nonce U = uG
	return adaptor.u.X.Cmp(targetPoint.X) == 0
}
