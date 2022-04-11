package trie

import (
	"optimism-trie/rlp"
	"optimism-trie/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type NodeType int

const (
	BranchNode NodeType = iota
	ExtensionNode
	LeafNode
)

type TrieNode struct {
	encoded []byte
	decoded []rlp.RLPItem
}

const (
	TREE_RADIX                    = 16
	BRANCH_NODE_LENGTH            = TREE_RADIX + 1
	LEAF_OR_EXTENSION_NODE_LENGTH = 2
	PREFIX_EXTENSION_EVEN         = 0
	PREFIX_EXTENSION_ODD          = 1
	PREFIX_LEAF_EVEN              = 2
	PREFIX_LEAF_ODD               = 3
)

var RLP_NULL = []byte{0x80}

func VerifyInclusionProof(key, expected, proof []byte, root common.Hash) bool {
	exists, value := Get(key, proof, root)
	return exists && utils.Equal(value, expected)
}

func Get(key, proof []byte, root common.Hash) (bool, []byte) {
	parsedProof := parseProof(proof)
	pathLength, keyRemainder, isFinalNode := walkNodePath(parsedProof, key, root)

	exists := len(keyRemainder) == 0
	if !exists || !isFinalNode {
		panic("provided proof is invalid")
	}

	var value []byte
	if exists {
		value = getNodeValue(parsedProof[pathLength-1])
	}

	return exists, value
}

func walkNodePath(proof []TrieNode, compressedKey []byte, root common.Hash) (uint64, []byte, bool) {
	var (
		pathLength = uint64(0)
		key        = utils.ToNibbles(compressedKey)

		currentNodeID       = root
		currentKeyIndex     = uint64(0)
		currentKeyIncrement = uint64(0)
		currentNode         TrieNode
	)

	for i := range proof {
		currentNode = proof[i]
		currentKeyIndex += currentKeyIncrement
		pathLength += 1

		if currentKeyIndex == 0 && keccak256(currentNode.encoded) != currentNodeID {
			panic("invalid root hash")
		} else if len(currentNode.encoded) >= 32 && keccak256(currentNode.encoded) != currentNodeID {
			panic("invalid large internal hash")
		} else if utils.ToBytes32(currentNode.encoded) != currentNodeID {
			panic("invalid internal node hash")
		}

		if len(currentNode.decoded) == BRANCH_NODE_LENGTH {
			if currentKeyIndex == uint64(len(key)) {
				// We've hit the end the key
				// meaning the value should be within this branch node
				break
			} else {
				// We're not at the end of the key yet.
				// Figure out what next node ID should be and continue.
				branchKey := key[currentKeyIndex]
				nextNode := currentNode.decoded[branchKey]
				currentNodeID = getNodeID(nextNode)
				currentKeyIncrement += 1
				continue
			}
		} else if len(currentNode.decoded) == LEAF_OR_EXTENSION_NODE_LENGTH {
			path := getNodePath(currentNode)
			prefix := int(path[0])
			offset := 2 - (prefix % 2)
			pathRemainder := utils.SliceEnd(path, uint64(offset))
			keyRemainder := utils.SliceEnd(key, uint64(currentKeyIndex))
			sharedNibbleLength := getSharedNibbleLength(pathRemainder, keyRemainder)

			if prefix == PREFIX_LEAF_EVEN || prefix == PREFIX_LEAF_ODD {
				if uint64(len(pathRemainder)) == sharedNibbleLength && uint64(len(keyRemainder)) == sharedNibbleLength {
					// The key within this leaf matches our key exactly.
					// Increment the key index to reflect that we have no remainder.
					currentKeyIndex += sharedNibbleLength
				}
				currentNodeID = utils.ToBytes32(RLP_NULL)
				break
			} else if prefix == PREFIX_EXTENSION_EVEN || prefix == PREFIX_EXTENSION_ODD {
				if sharedNibbleLength != uint64(len(pathRemainder)) {
					// Our extension node is not identical to the remainder.
					// We've hit the end of this path
					// updates will need to modify this extension
					currentNodeID = utils.ToBytes32(RLP_NULL)
					break
				} else {
					// Our extension shares some nibbles.
					// Carry on to the next node.
					currentNodeID = getNodeID(currentNode.decoded[1])
					currentKeyIncrement = sharedNibbleLength
					continue
				}
			} else {
				panic("received a node with an unknown prefix")
			}
		} else {
			panic("received an unparseable node")
		}
	}

	isFinalNode := currentNodeID == utils.ToBytes32(RLP_NULL)
	return pathLength, utils.SliceEnd(key, currentKeyIndex), isFinalNode
}

func parseProof(proof []byte) []TrieNode {
	nodes := rlp.ReadListBytes(proof)
	out := make([]TrieNode, 0, len(nodes))
	for _, node := range nodes {
		encoded := rlp.ReadBytes(node)
		out = append(out, TrieNode{encoded: encoded, decoded: rlp.ReadListBytes(encoded)})
	}
	return out
}

func getNodeID(node rlp.RLPItem) common.Hash {
	if node.Length < 32 {
		return utils.ToBytes32(rlp.ReadRawBytes(node))
	}
	return utils.ToBytes32(rlp.ReadBytes(node))
}

func getNodePath(node TrieNode) []byte {
	return utils.ToNibbles(rlp.ReadBytes(node.decoded[0]))
}

func getNodeValue(node TrieNode) []byte {
	return rlp.ReadBytes(node.decoded[len(node.decoded)-1])
}

func getSharedNibbleLength(a, b []byte) uint64 {
	var (
		shared = 0
		short  []byte
		long   []byte
	)
	if len(a) < len(b) {
		short = a
		long = b
	} else {
		short = b
		long = a
	}
	for i := range short {
		if short[i] != long[i] {
			break
		}
		shared += 1
	}
	return uint64(shared)
}

func keccak256(in []byte) common.Hash {
	return common.BytesToHash(crypto.Keccak256(in))
}
