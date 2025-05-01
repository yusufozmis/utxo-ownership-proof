package Stark

import (
	"encoding/hex"
	"fmt"
	"utxo-ownership-proof/Bitcoin"
	common "utxo-ownership-proof/Common"
)

func UnspentProof(ch *Channel, blockNumber int, unspentutxo common.Witness) []Polynomial {

	var constraintPolynomials []Polynomial
	// Collects all of the transaction id's from a given block number
	txidList := Bitcoin.GetBlockTxIDs(Bitcoin.BlockHash(blockNumber))
	//Gets the raw transaction data of each transaction in that block.
	var rawTxList []string
	for i, txid := range txidList {
		fmt.Println("txlist", i)
		rawTx := Bitcoin.RawTx(txid)
		rawTxConstraint := ProveRawTx(rawTx, txidList[i])
		rawTxList = append(rawTxList, rawTx)
		constraintPolynomials = append(constraintPolynomials, rawTxConstraint)
	}

	// Extracts the Vins and their corresponding vout's from raw transactions
	var vinRefs [][]common.VinReference
	for _, rawTx := range rawTxList {
		vinRefs = append(vinRefs, Bitcoin.GetVinReferences(rawTx))
	}

	//Proves that all of the Vin.TXid and Vin.Vout' that getvinreferences returned
	// are included in rawtx
	for i, vinRef := range vinRefs {
		rawTx := rawTxList[i]
		for _, vin := range vinRef {
			vinConstraints := ProveVin(rawTx, vin)
			constraintPolynomials = append(constraintPolynomials, vinConstraints...)
		}
	}
	//Proves that the extracted vin's corresponds to transaction id's, ensuring that they're nor just random hashes.
	for _, vinRef := range vinRefs {
		for _, vin := range vinRef {
			if vin.Txid == "0000000000000000000000000000000000000000000000000000000000000000" {
				continue
			}
			spv := Bitcoin.GetInclusion(vin.Txid)
			merkleConstraint := MerkleProofStark(spv.InclusionProof, vin.Txid, spv.Pos)
			constraintPolynomials = append(constraintPolynomials, merkleConstraint)
		}
	}

	var txConcat string
	txConcat += unspentutxo.Txid
	txConcat += hex.EncodeToString(IntToBytes(unspentutxo.Vout))

	//Proves that txid || vout  != vin.Txid || vin.Vout
	for _, vinRef := range vinRefs {
		for _, vin := range vinRef {
			var vinConcat string
			vinConcat += vin.Txid
			vinConcat += hex.EncodeToString(IntToBytes(vin.Vout))

			constr := AssertNotEqual(txConcat, vinConcat)
			constraintPolynomials = append(constraintPolynomials, constr)
		}
	}
	//Generates the merkle tree from the transaction id's and asserts its validity.
	var txidBytes []string
	for _, hexStr := range txidList {
		b, _ := hex.DecodeString(hexStr)
		b = Bitcoin.ReverseBytes(b)
		txidBytes = append(txidBytes, hex.EncodeToString(b))
	}
	tree := Bitcoin.BuildBitcoinMerkleTree(txidBytes)

	root := tree[len(tree)-1][0]
	rootBytes, _ := hex.DecodeString(root)
	rootBytes = Bitcoin.ReverseBytes(rootBytes)
	rt := fmt.Sprintf("%x", rootBytes)

	constrMerkle := ProveMerkleTree(tree, rt)

	constr := AssertEqual(rt, Bitcoin.BlockMerkleRoot(Bitcoin.BlockHash(blockNumber)))

	//Sends the scanned Bitcoin block over the channel
	ch.Send(rt)
	constraintPolynomials = append(constraintPolynomials, constr)
	constraintPolynomials = append(constraintPolynomials, constrMerkle...)
	return constraintPolynomials
}
