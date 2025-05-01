package Bitcoin

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"

	"github.com/btcsuite/btcd/wire"
)

func encodeVarInt(n uint64) []byte {
	switch {
	case n < 0xfd:
		return []byte{byte(n)}
	case n <= 0xffff:
		return append([]byte{0xfd}, byte(n), byte(n>>8))
	case n <= 0xffffffff:
		return append([]byte{0xfe}, byte(n), byte(n>>8), byte(n>>16), byte(n>>24))
	default:
		return append([]byte{0xff},
			byte(n),
			byte(n>>8),
			byte(n>>16),
			byte(n>>24),
			byte(n>>32),
			byte(n>>40),
			byte(n>>48),
			byte(n>>56))
	}
}

// Parses Bitcoin Raw Transaction into meaningful parts (and concats vin || vout for inputs)
func TraceConcatVins(rawHex string) [][]byte {
	rawBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		panic(err)
	}
	tx := wire.NewMsgTx(wire.TxVersion)
	err = tx.Deserialize(bytes.NewReader(rawBytes))
	if err != nil {
		panic(err)
	}

	var trace [][]byte

	version := make([]byte, 4)
	binary.LittleEndian.PutUint32(version, uint32(tx.Version))
	trace = append(trace, version)

	inputCount := encodeVarInt(uint64(len(tx.TxIn)))
	trace = append(trace, inputCount)

	for _, txIn := range tx.TxIn {
		var concatPrev []byte
		prevHash := txIn.PreviousOutPoint.Hash.CloneBytes()
		ReverseBytes(prevHash)
		concatPrev = append(concatPrev, prevHash...)

		vout := make([]byte, 4)
		binary.LittleEndian.PutUint32(vout, uint32(txIn.PreviousOutPoint.Index))
		concatPrev = append(concatPrev, vout...)

		trace = append(trace, concatPrev)

		scriptLen := encodeVarInt(uint64(len(txIn.SignatureScript)))
		trace = append(trace, scriptLen)

		if len(txIn.SignatureScript) > 0 {
			trace = append(trace, txIn.SignatureScript)
		}

		seq := make([]byte, 4)
		binary.LittleEndian.PutUint32(seq, txIn.Sequence)
		trace = append(trace, seq)
	}

	outputCount := encodeVarInt(uint64(len(tx.TxOut)))
	trace = append(trace, outputCount)

	for _, txOut := range tx.TxOut {
		value := make([]byte, 8)
		binary.LittleEndian.PutUint64(value, uint64(txOut.Value))
		trace = append(trace, value)

		pkLen := encodeVarInt(uint64(len(txOut.PkScript)))
		trace = append(trace, pkLen)

		if len(txOut.PkScript) > 0 {
			trace = append(trace, txOut.PkScript)
		}
	}

	lockTime := make([]byte, 4)
	binary.LittleEndian.PutUint32(lockTime, tx.LockTime)
	trace = append(trace, lockTime)

	return trace
}

// Parses Bitcoin Transaction into meaningful parts, then concats inputs and outputs(i.e. index 2 is prevtxid || vout || scriptsiglenght || scriptsig || sequence)
// and outputs are (amount || pkscript lenght || pkscript)
func TraceConcatAll(rawHex string) [][]byte {
	rawBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		panic(err)
	}
	tx := wire.NewMsgTx(wire.TxVersion)
	err = tx.Deserialize(bytes.NewReader(rawBytes))
	if err != nil {
		panic(err)
	}

	var trace [][]byte

	// Version
	version := make([]byte, 4)
	binary.LittleEndian.PutUint32(version, uint32(tx.Version))
	trace = append(trace, version)

	// Input count (VarInt)
	inputCount := encodeVarInt(uint64(len(tx.TxIn)))
	trace = append(trace, inputCount)

	// inputs
	for _, txIn := range tx.TxIn {
		var input []byte
		prevHash := txIn.PreviousOutPoint.Hash.CloneBytes()
		ReverseBytes(prevHash)
		input = append(input, prevHash...)

		// Vout
		vout := make([]byte, 4)
		binary.LittleEndian.PutUint32(vout, uint32(txIn.PreviousOutPoint.Index))
		input = append(input, vout...)

		// ScriptSig length
		scriptLen := encodeVarInt(uint64(len(txIn.SignatureScript)))
		input = append(input, scriptLen...)

		// ScriptSig
		if len(txIn.SignatureScript) > 0 {
			input = append(input, txIn.SignatureScript...)
		}

		// Sequence
		seq := make([]byte, 4)
		binary.LittleEndian.PutUint32(seq, txIn.Sequence)
		input = append(input, seq...)

		trace = append(trace, input)
	}
	// Output count
	outputCount := encodeVarInt(uint64(len(tx.TxOut)))
	trace = append(trace, outputCount)

	// Each output
	for _, txOut := range tx.TxOut {
		// Value
		var output []byte
		value := make([]byte, 8)
		binary.LittleEndian.PutUint64(value, uint64(txOut.Value))
		output = append(output, value...)

		// PkScript length
		pkLen := encodeVarInt(uint64(len(txOut.PkScript)))
		output = append(output, pkLen...)

		// PkScript
		if len(txOut.PkScript) > 0 {
			output = append(output, txOut.PkScript...)
		}
		trace = append(trace, output)
	}

	// LockTime
	lockTime := make([]byte, 4)
	binary.LittleEndian.PutUint32(lockTime, tx.LockTime)
	trace = append(trace, lockTime)

	return trace
}
