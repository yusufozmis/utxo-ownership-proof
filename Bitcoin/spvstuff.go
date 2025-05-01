package Bitcoin

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type Block struct {
	ID                string  `json:"id"`
	Height            int     `json:"height"`
	Version           int     `json:"version"`
	Timestamp         int64   `json:"timestamp"`
	TxCount           int     `json:"tx_count"`
	Size              int     `json:"size"`
	Weight            int     `json:"weight"`
	MerkleRoot        string  `json:"merkle_root"`
	PreviousBlockHash string  `json:"previousblockhash"`
	MedianTime        int64   `json:"mediantime"`
	Nonce             int     `json:"nonce"`
	Bits              int     `json:"bits"`
	Difficulty        float64 `json:"difficulty"`
}

type SPV struct {
	BlockHeight    int      `json:"block_height"`
	InclusionProof []string `json:"merkle"`
	Pos            int      `json:"pos"`
}

// Gets the SPV proof of a given Transaction
func GetInclusion(txid string) SPV {
	url := fmt.Sprintf("https://mempool.space/api/tx/%s/merkle-proof", txid)

	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Println("statuscode", resp.StatusCode)
		fmt.Println("status", resp.Status)
		panic("unexpected HTTP status: ")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic("reading body failed: ")
	}

	var result SPV
	if err := json.Unmarshal(body, &result); err != nil {
		panic("JSON unmarshal failed")
	}

	return result
}

// Gets the merkle root of a given Bitcoin block.
func BlockMerkleRoot(blockHash string) string {
	headerURL := fmt.Sprintf("https://mempool.space/api/block/%s", blockHash)
	resp, err := http.Get(headerURL)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	var block Block
	err2 := json.Unmarshal(bodyBytes, &block)
	if err2 != nil {
		panic(err2)
	}
	return block.MerkleRoot
}

// Necessary to ensure Bitcoin's little-endian formatting
func ReverseBytes(input []byte) []byte {
	output := make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		output[len(input)-1-i] = input[i]
	}
	return output
}
