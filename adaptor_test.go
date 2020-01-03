package dcr_adaptor_sigs

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v2"
	"github.com/decred/dcrd/dcrec"
	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v2/schnorr"
	"github.com/decred/dcrd/dcrutil/v2"
	"github.com/decred/dcrd/txscript/v2"
	"github.com/decred/dcrd/wire"
)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

type mockNoncer struct {
	r, t []byte
}

func (m *mockNoncer) Nonces() ([]byte, []byte, error) {
	return m.r, m.t, nil
}

// newMockNoncer returns a new mock noncer with known fixed and valid nonces.
func newMockNoncer() *mockNoncer {
	return &mockNoncer{
		r: mustDecodeHex("42526f5567685420746f2075206279204465637265442b6d407468657573645f"),
		t: mustDecodeHex("646170742073696773207220776f6f742120747920412e506f656c7374726121"),
	}
}

// TestAdaptorSigStatic tests whether the adaptor signature scheme works for
// static, predetermined keys.
func TestAdaptorSigStatic(t *testing.T) {
	privKeyData, _ := hex.DecodeString("0102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F00")
	privKey, pubKey := secp256k1.PrivKeyFromBytes(privKeyData)
	noncer := newMockNoncer()
	msgData, _ := hex.DecodeString("0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F")

	sig, err := Sign(privKey, msgData, noncer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The full signature should be a valid schnorr sig.
	valid := schnorr.Verify(pubKey, msgData, sig.R, sig.S)
	if !valid {
		t.Fatalf("signature failed verification")
	}

	// The adaptor sig should be a valid partial sig.
	validAdaptor := VerifyAdaptorSig(sig.R, sig.RNonce, pubKey, sig.AdaptorSig, msgData)
	if !validAdaptor {
		t.Fatal("adaptor signature failed verification")
	}

	// But it should *not* be a valid schnorr sig.
	adaptorIsFullyValid := schnorr.Verify(pubKey, msgData, sig.R, sig.AdaptorSig)
	if adaptorIsFullyValid {
		t.Fatal("adaptor sig still verified as valid when it should not")
	}

	// We should be able to extract the secret from the difference between
	// the full sig and the adaptor sig.
	gotSecret := RecoverSecret(sig.S, sig.AdaptorSig, sig.Flags)
	if !bytes.Equal(gotSecret, sig.Secret) {
		t.Fatalf("extracted secret not equal to generated. want=%x got=%x",
			sig.Secret, gotSecret)
	}

	// And the secret should equal the original `t` nonce data.
	if !bytes.Equal(gotSecret, noncer.t) {
		t.Fatalf("extracted secret not equal to original t nonce. want=%x got=%x",
			noncer.t, gotSecret)
	}

	// Conversely, having been given the adaptor sig, public nonce (R+T)
	// and the secret we should be able to combine them into a valid
	// signature.
	assembledSig := AssembleFullSig(sig.AdaptorSig, sig.Secret, sig.Flags)
	validAssembled := schnorr.Verify(pubKey, msgData, sig.R, assembledSig)
	if !validAssembled {
		t.Fatalf("assembled signature failed verification")
	}
}

// BenchmarkSigning benchmarks generating adaptor signatures.
func BenchmarkSigning(b *testing.B) {
	privKeyData, _ := hex.DecodeString("0102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F00")
	privKey, _ := secp256k1.PrivKeyFromBytes(privKeyData)

	msgData, _ := hex.DecodeString("0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F")
	n := uint32(b.N)
	noncer := newMockNoncer()

	b.ResetTimer()
	for i := uint32(0); i < n; i++ {
		binary.BigEndian.PutUint32(msgData, i)
		_, err := Sign(privKey, msgData, noncer)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

// TestAdaptorSigTxs tests generating an adaptor signature of a certain
// transaction.
func TestAdaptorSigTxs(t *testing.T) {
	privKeyData, _ := hex.DecodeString("0102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F00")
	privKey, pubKey := secp256k1.PrivKeyFromBytes(privKeyData)

	// Generate a Pay To Schnorr Alt PubKey Hash address.
	net := chaincfg.TestNet3Params()
	pubKeyHash := dcrutil.Hash160(pubKey.Serialize())
	addr, err := dcrutil.NewAddressPubKeyHash(pubKeyHash, net, dcrec.STSchnorrSecp256k1)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("P2SAPKH Address: %s", addr.Address())
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}
	const scriptVerifyFlags = txscript.ScriptDiscourageUpgradableNops | // standardness
		txscript.ScriptVerifyCleanStack | // consensus
		txscript.ScriptVerifyCheckLockTimeVerify | // consensus
		txscript.ScriptVerifyCheckSequenceVerify | // consensus (lnfeatures)
		txscript.ScriptVerifySHA256 // consensus (lnfeatures)

	// Prepare the transaction that spends from that address.
	emptyPkhPkscript := [25]byte{
		0:  0x76,
		1:  0xa9,
		2:  0x14,
		23: 0x88,
		24: 0xac,
	}
	prevOutHash, err := chainhash.NewHashFromStr("b82c5ba434098875e663e0dbb76df6e19afedb58096b750e888922bb58ca5c60")
	if err != nil {
		t.Fatal(err)
	}
	prevOutpoint := &wire.OutPoint{
		Hash:  *prevOutHash,
		Index: 1,
		Tree:  wire.TxTreeRegular,
	}
	spendTx := &wire.MsgTx{
		TxIn: []*wire.TxIn{
			&wire.TxIn{
				PreviousOutPoint: *prevOutpoint,
			},
		},
		TxOut: []*wire.TxOut{
			&wire.TxOut{
				Value:    100000,
				PkScript: emptyPkhPkscript[:],
			},
		},
	}

	// Calculate the transaction hash that needs signing.
	sigHash, err := txscript.CalcSignatureHash(pkScript, txscript.SigHashAll,
		spendTx, 0, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Sign via the adaptor sig method.
	sig, err := Sign(privKey, sigHash, newMockNoncer())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pkData := pubKey.Serialize()

	// Verify the signature is correct.
	valid := schnorr.Verify(pubKey, sigHash, sig.R, sig.S)
	if !valid {
		t.Fatal("sig verification failed")
	}

	// Fill-in the signature data.
	schnorrSig := schnorr.NewSignature(sig.R, sig.S).Serialize()
	schnorrSig = append(schnorrSig, byte(txscript.SigHashAll))
	sigScript, err := txscript.NewScriptBuilder().AddData(schnorrSig).AddData(pkData).Script()
	if err != nil {
		t.Fatal(err)
	}
	spendTx.TxIn[0].SignatureScript = sigScript

	// The script for this transaction should be valid.
	vm, err := txscript.NewEngine(pkScript, spendTx, 0, scriptVerifyFlags,
		0, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = vm.Execute()
	if err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	// Log the full spend transaction data.
	txBytes, _ := spendTx.Bytes()
	t.Logf("Spend transaction:\n%x", txBytes)
}