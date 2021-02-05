package dcr_adaptor_sigs

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrd/dcrec/secp256k1/v3/schnorr"
)

type SecretScalar [32]byte

func (s *SecretScalar) PublicPoint() *secp256k1.PublicKey {
	return pubkeyFromPrivData(s[:])
}

// AdaptorSignature is the partial adaptor signature.
type AdaptorSignature struct {
	t      *secp256k1.PublicKey // T = secret * G
	u      *secp256k1.PublicKey // U = uG
	sPrime secp256k1.ModNScalar
}

// AdaptorSignatureSerializeLen is the length of a serialized adaptor
// signature.
const AdaptorSignatureSerializeLen = 32 + 32 + 32 + 1

func ParseAdaptorSignature(b []byte) (*AdaptorSignature, error) {
	if len(b) != AdaptorSignatureSerializeLen {
		return nil, fmt.Errorf("slice does not have required length")
	}

	var t, u *secp256k1.PublicKey
	var err error
	flags := b[0]
	tFlags := 0x2 | (flags & 0x1)
	uFlags := 0x2 | ((flags & 0x2) >> 1)

	parsePk := func(f byte, b []byte) (*secp256k1.PublicKey, error) {
		pkb := make([]byte, 33)
		pkb[0] = f
		copy(pkb[1:], b)
		return secp256k1.ParsePubKey(pkb)
	}

	if t, err = parsePk(tFlags, b[1:33]); err != nil {
		return nil, err
	}
	if u, err = parsePk(uFlags, b[33:65]); err != nil {
		return nil, err
	}
	var s secp256k1.ModNScalar
	if s.SetByteSlice(b[65:97]) {
		return nil, fmt.Errorf("serialized sprime overflowed ModNScalar")
	}
	return &AdaptorSignature{
		t:      t,
		u:      u,
		sPrime: s,
	}, nil
}

// R returns the full public nonce point, used to validate the full signature.
func (asig *AdaptorSignature) R() *secp256k1.PublicKey {
	r, _ := produceR(asig.t, asig.u)
	return r
}

// U returns the random public nonce, used to validate an adaptor signature.
func (asig *AdaptorSignature) U() *secp256k1.PublicKey {
	return asig.u
}

// T returns the target public nonce, used to validate an adaptor signature.
func (asig *AdaptorSignature) T() *secp256k1.PublicKey {
	return asig.t
}

func (asig *AdaptorSignature) Serialize() []byte {
	tBytes := asig.t.SerializeCompressed()
	uBytes := asig.u.SerializeCompressed()
	sBytes := asig.sPrime.Bytes()

	// The first byte has two flags (LSB): whether the Y coordinate for T
	// is odd and whether the Y coordinate for U is odd.
	var flags byte
	const isOddMask = 0x01
	flags = flags | tBytes[0]&isOddMask<<0
	flags = flags | uBytes[0]&isOddMask<<1

	all := make([]byte, 0, len(tBytes)+len(uBytes)+len(sBytes)+1)
	all = append(all, flags)
	all = append(all, tBytes[1:]...)
	all = append(all, uBytes[1:]...)
	all = append(all, sBytes[:]...)
	return all
}

// Verify returns whether the given adaptor sig is a valid **adaptor** sig.
// Note that valid adaptor signatures are *NOT* valid Schnorr signatures.
func (asig *AdaptorSignature) Verify(msg []byte, pubKey *secp256k1.PublicKey) bool {
	return VerifyAdaptorSig(asig, pubKey, msg)
}

// Noncer defines a single function Nonces that is used to generate nonces for
// adaptor signatures.
//
// TODO: deal with failed signatures (recreate nonce).
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
	privBytes := priv.Serialize()
	b := secp256k1.NonceRFC6979(privBytes, msg, nil, nil, 0)
	var u [32]byte
	b.PutBytes(&u)
	return u
}

// ExternalNoncer allows generation of a specific nonce when generating an
// adaptor signature.
//
// NOTE: proper nonce selection is CRITICALLY important for safe application of
// adaptor signatures, so implementors MUST understand how to do it, otherwise
// an adaptor signature might disclose the private key.
//
// Callers are encouraged *NOT* to use this noncer, but instead rely on
// RFC6979Noncer or RandomNoncer as those are generally safer to use.
type ExternalNoncer func() [32]byte

func (en ExternalNoncer) nonce(priv *secp256k1.PrivateKey, msg []byte) [32]byte {
	return en()
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
	rmhx.Mul(rmHash, encodedBytesToBigInt(privKey.Serialize()))

	// Calculate the Adaptor Signature s' = u - Hash(T+U || m) * x
	sPrime := new(big.Int)
	if inverted {
		sPrime.Sub(curve.N, uNonce)
		sPrime.Sub(sPrime, rmhx)
	} else {
		sPrime.Sub(uNonce, rmhx)
	}
	sPrime.Mod(sPrime, curve.N)
	var sPrimeModN secp256k1.ModNScalar
	sPrimeModN.SetByteSlice(sPrime.Bytes())

	// TODO: bounds check adaptorSig (if == 0)

	adaptor := &AdaptorSignature{
		t:      T,
		u:      U,
		sPrime: sPrimeModN,
	}
	return adaptor, R, inverted
}

// AdaptorSign produces an adaptor (partial) signature for the given data.
func AdaptorSign(privKey *secp256k1.PrivateKey, msg []byte, T *secp256k1.PublicKey, noncer Noncer) (*AdaptorSignature, error) {
	u := noncer.nonce(privKey, msg)
	sig, _, _ := adaptorSign(privKey, msg, T, &u)

	// Clear out the private nonce from memory.
	for i := range u[:] {
		u[i] = 0
	}
	return sig, nil
}

// assembleFullSig assembles the full signature given some adaptor sig and the
// secret scalar.
func assembleFullSig(adaptor *AdaptorSignature, secret *SecretScalar,
	R *secp256k1.PublicKey, inverted bool) (*schnorr.Signature, error) {

	secretBig := new(big.Int)
	secretBig.SetBytes(secret[:])
	secretBig.Mod(secretBig, secp256k1.S256().N)

	sPrime := new(big.Int)
	sPrimeBytes := adaptor.sPrime.Bytes()
	sPrime.SetBytes(sPrimeBytes[:])

	s := new(big.Int)
	if inverted {
		s.Sub(sPrime, secretBig)
	} else {
		s.Add(sPrime, secretBig)
	}
	s.Mod(s, secp256k1.S256().N)

	var rJacobian secp256k1.JacobianPoint
	R.AsJacobian(&rJacobian)

	var sModN secp256k1.ModNScalar
	if sModN.SetByteSlice(s.Bytes()) {
		return nil, fmt.Errorf("s overflowed ModNScalar")
	}

	return schnorr.NewSignature(&rJacobian.X, &sModN), nil
}

// AssembleFullSig allows one to (re-)assemble the fully valid signature after
// one has seen both the adaptor signature and the secret.
func AssembleFullSig(adaptor *AdaptorSignature, secret *SecretScalar) (*schnorr.Signature, error) {
	R, inverted := produceR(adaptor.u, adaptor.t)
	return assembleFullSig(adaptor, secret, R, inverted)
}

// RecoverSecret allows one to recover the secret nonce (the "t" secret nonce)
// after one has seen both the full and adaptor signatures.
func RecoverSecret(sig *schnorr.Signature, adaptor *AdaptorSignature) SecretScalar {
	secret := new(big.Int)
	sPrime := new(big.Int)
	sPrimeBytes := adaptor.sPrime.Bytes()
	sPrime.SetBytes(sPrimeBytes[:])
	sigBytes := sig.Serialize()
	s := new(big.Int)
	s.SetBytes(sigBytes[32:64])

	_, inverted := produceR(adaptor.u, adaptor.t)
	if inverted {
		secret.Sub(sPrime, s)
	} else {
		secret.Sub(s, sPrime)
	}
	secret.Mod(secret, secp256k1.S256().N)
	var t SecretScalar
	copy(t[:], secret.Bytes())
	return t
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
	return adaptor.u.X().Cmp(targetPoint.X()) == 0
}
