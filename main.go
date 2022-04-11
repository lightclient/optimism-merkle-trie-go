package main

import (
	"fmt"
	"optimism-trie/rlp"
	"optimism-trie/utils"

	gRlp "github.com/ethereum/go-ethereum/rlp"
)

func main() {
	// var buf interface{}
	// if err := gRlp.DecodeBytes([]byte{0x81, 0x81}, &buf); err != nil {
	//         fmt.Printf("error: %s\n", err)
	//         return
	// }
	// fmt.Println(buf)
	enc, err := gRlp.EncodeToBytes([]byte{})
	if err != nil {
		fmt.Printf("error: %s\n", err)
		return
	}
	fmt.Println(enc)
	utils.Equal([]byte{}, []byte{})
	_ = rlp.DataItem
}
