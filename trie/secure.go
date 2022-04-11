package trie

import "github.com/ethereum/go-ethereum/common"

func VerifySecureInclusionProof(key, value, proof []byte, root common.Hash) bool {
	return VerifyInclusionProof(getSecureKey(key), value, proof, root)
}

func GetSecure(key, proof []byte, root common.Hash) (bool, []byte) {
	return Get(getSecureKey(key), proof, root)
}

func getSecureKey(key []byte) []byte {
	return keccak256(key).Bytes()
}
