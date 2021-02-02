package dcr_adaptor_sigs

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrd/txscript/v3"
	"github.com/decred/dcrd/wire"
)

// TxInSignature calculates the adaptor signature for a given transaction
// input.
//
// TODO: this shouldn't live in this package since it's an application of an
// adaptor sig rather than part of the generic adaptor sig toolset.
func TxInSignature(tx *wire.MsgTx, idx int, subScript []byte,
	hashType txscript.SigHashType, privKey *secp256k1.PrivateKey,
	T *secp256k1.PublicKey, noncer Noncer) (*AdaptorSignature, error) {

	// Calculate the transaction hash that needs signing.
	sigHash, err := txscript.CalcSignatureHash(subScript, hashType,
		tx, idx, nil)
	if err != nil {
		return nil, err
	}

	// Sign via the adaptor sig method.
	return AdaptorSign(privKey, sigHash, T, noncer)
}
