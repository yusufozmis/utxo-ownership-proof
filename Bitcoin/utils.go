package Bitcoin

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	common "utxo-ownership-proof/Common"

	"github.com/btcsuite/btcd/wire"
)

func GetBlockTxIDs(blockHash string) []string {
	url := fmt.Sprintf("https://blockstream.info/api/block/%s/txids", blockHash)
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	var txids []string
	if err := json.NewDecoder(resp.Body).Decode(&txids); err != nil {
		log.Fatal(err)
	}
	return txids
}
func RawTxRest(txid string) string {

	url := fmt.Sprintf("https://mempool.space/api/tx/%s/hex", txid)
	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	return string(body)
}

func RawTx(txid string) string {

	url := "https://quiet-tame-wish.btc.quiknode.pro/d56d54936e54ece4c68b2b3030df95afae620aff/"

	requestBody, err := json.Marshal(map[string]interface{}{
		"method":  "getrawtransaction",
		"params":  []interface{}{txid, 0},
		"id":      1,
		"jsonrpc": "2.0",
	})
	if err != nil {
		return "err1"
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return "err2"
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "err3"
	}

	var result struct {
		Result string      `json:"result"`
		Error  interface{} `json:"error"`
	}
	err = json.Unmarshal(bodyBytes, &result)
	if err != nil {
		return "err4"
	}

	if result.Error != nil {
		return fmt.Sprintf("RPC Error: %v", result.Error)
	}

	return result.Result
}

func GetVinReferences(rawTx string) []common.VinReference {
	rawBytes, err := hex.DecodeString(rawTx)
	if err != nil {
		panic(err)
	}
	tx := wire.NewMsgTx(wire.TxVersion)
	err = tx.Deserialize(bytes.NewReader(rawBytes))
	if err != nil {
		panic(err)
	}
	var vinRefs []common.VinReference

	for _, txIn := range tx.TxIn {
		var vin common.VinReference
		vin.Txid = hex.EncodeToString(txIn.PreviousOutPoint.Hash.CloneBytes())
		vin.Txid = hex.EncodeToString(ReverseBytes(txIn.PreviousOutPoint.Hash.CloneBytes()))

		vout := make([]byte, 4)
		binary.LittleEndian.PutUint32(vout, uint32(txIn.PreviousOutPoint.Index))

		vin.Vout = int(binary.LittleEndian.Uint32(vout))

		vinRefs = append(vinRefs, vin)
	}
	return vinRefs

}

// Gets the Inputs (prevtxhash and vout) for a given tx.
func GetVinReferencesOld(rawTxHex string) []common.VinReference {

	rawTxBytes, err := hex.DecodeString(rawTxHex)
	if err != nil {
		log.Fatalf("Error decoding raw transaction: %v", err)
	}

	if len(rawTxBytes) < 5 {
		log.Fatalf("Raw transaction is too short.")
	}
	var vinRefs []common.VinReference
	offset := 4 // Skip version

	// Check if it's a SegWit transaction
	if rawTxBytes[offset] == 0x00 && rawTxBytes[offset+1] == 0x01 {
		offset += 2 // Skip marker and flag
	}

	// Read input count (varint)
	inputCount := int(rawTxBytes[offset])
	offset++

	if inputCount == 0 {
		fmt.Println("No inputs found")
		return nil
	}

	for i := 0; i < inputCount; i++ {
		if offset+36 > len(rawTxBytes) {
			log.Fatalf("Not enough data to read input %d", i)
		}

		txidLE := rawTxBytes[offset : offset+32]
		txid := ReverseBytes(txidLE)
		offset += 32

		voutBytes := rawTxBytes[offset : offset+4]
		vout := int(binary.LittleEndian.Uint32(voutBytes))
		offset += 4

		vinRefs = append(vinRefs, common.VinReference{
			Txid: hex.EncodeToString(txid),
			Vout: vout,
		})

		// Read ScriptSig length (varint)
		scriptLen := int(rawTxBytes[offset])
		offset++

		offset += scriptLen // skip scriptSig
		offset += 4         // skip sequence
	}
	return vinRefs
}

// Returns the blockhash for a given blocknumber
func BlockHash(blockNumber int) string {

	headerURL := fmt.Sprintf("https://mempool.space/api/block-height/%d", blockNumber)
	resp, err := http.Get(headerURL)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	blockHash := string(bodyBytes)

	return blockHash
}
