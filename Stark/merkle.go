package Stark

import (
	"crypto/sha256"
	"fmt"
)

type Node struct {
	hash  string
	Left  *Node
	Right *Node
}

func NewNode(data string) Node {
	hash := sha256.Sum256([]byte(data))
	return Node{
		hash: fmt.Sprintf("%x", hash[:]),
	}
}
func MerkleTree(leavesField []FiniteFieldElement) [][]Node {
	t := len(leavesField)
	leaves := make([]string, t)

	for i := 0; i < t; i++ {
		leaves[i] = leavesField[i].Value.String()
	}

	var tree [][]Node
	level := []Node{}

	if len(leaves)%2 != 0 {
		leaves = append(leaves, leaves[len(leaves)-1])
	}
	for _, leaf := range leaves {
		level = append(level, NewNode(leaf))
	}
	tree = append(tree, level)

	for len(level) > 1 {
		var nextLevel []Node
		for i := 0; i < len(level); i += 2 {
			var left, right Node
			left = level[i]
			if i+1 < len(level) {
				right = level[i+1]
			} else {
				right = left
			}

			combinedHash := NewNode(left.hash + right.hash)
			combinedHash.Left = &left
			combinedHash.Right = &right
			nextLevel = append(nextLevel, combinedHash)
		}
		tree = append(tree, nextLevel)
		level = nextLevel
	}

	return tree
}
func MerkleRoot(MerkleTree [][]Node) Node {
	t := len(MerkleTree)
	return MerkleTree[t-1][0]
}
func MerkleProof(merkleTree [][]Node, index int) []string {
	var proof []string
	t := len(merkleTree)
	for i := 0; i < t-1; i++ {
		if index >= len(merkleTree[i]) {
			break
		}
		if index%2 == 0 {
			if index+1 < len(merkleTree[i]) {
				proof = append(proof, merkleTree[i][index+1].hash)
			}
		} else {
			proof = append(proof, merkleTree[i][index-1].hash)
		}
		index = index / 2
	}
	return proof
}
func VerifyMerkleProof(proof []string, item string, root string, index int) bool {
	currentHash := NewNode(item).hash
	for _, proofElement := range proof {
		var combined string
		if index%2 == 0 {
			combined = currentHash + proofElement
		} else {
			combined = proofElement + currentHash
		}
		currentHash = NewNode(combined).hash
		index /= 2
	}
	return fmt.Sprintf("%x", []byte(currentHash)) == fmt.Sprintf("%x", []byte(root))
}
