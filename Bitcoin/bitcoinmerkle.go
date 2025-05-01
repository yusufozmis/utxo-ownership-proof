package Bitcoin

import (
	"crypto/sha256"
	"encoding/hex"
)

func DoubleSHA256(b []byte) []byte {
	h := sha256.Sum256(b)
	h2 := sha256.Sum256(h[:])
	return h2[:]
}

func BuildBitcoinMerkleTree(txids []string) [][]string {
	if len(txids) == 0 {
		return nil
	}

	var tree [][]string
	tree = append(tree, txids)

	for len(txids) > 1 {
		var newLevel []string
		for i := 0; i < len(txids); i += 2 {
			left, _ := hex.DecodeString(txids[i])
			var right []byte
			if i+1 < len(txids) {
				right, _ = hex.DecodeString(txids[i+1])
			} else {
				right = left
			}

			concat := append(left, right...)
			hashed := DoubleSHA256(concat)
			newLevel = append(newLevel, hex.EncodeToString(hashed))
		}

		tree = append(tree, newLevel)
		txids = newLevel
	}

	return tree
}

// Generates Merkle Trace from given Merkle Proof by appending intermediate hashes to the merkle proof.
// This function is used for proving the validity of a given merkle proof
func MerkleTrace(proof []string, leaf string, pos int) []string {
	var trace []string

	leafBytes, _ := hex.DecodeString(leaf)
	currentHash := ReverseBytes(leafBytes)

	trace = append(trace, leaf)

	for i := 0; i < len(proof); i++ {
		trace = append(trace, proof[i])

		proofElement, _ := hex.DecodeString(proof[i])
		proofElement = ReverseBytes(proofElement)

		var combined []byte
		if pos%2 == 0 {
			combined = append(currentHash, proofElement...)
		} else {
			combined = append(proofElement, currentHash...)
		}

		currentHash = DoubleSHA256(combined)

		resultHash := ReverseBytes(currentHash)
		trace = append(trace, hex.EncodeToString(resultHash))

		pos /= 2
	}
	return trace
}
