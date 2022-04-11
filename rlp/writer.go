package rlp

import (
	"encoding/binary"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

func WriteBytes(in []byte) []byte {
	if len(in) == 1 && in[0] < 0x80 {
		return in
	}
	length := writeLength(uint64(len(in)), 0x80)
	return append(length, in...)
}

func WriteList(in [][]byte) []byte {
	list := flatten(in)
	length := writeLength(uint64(len(list)), 0xc0)
	return append(length, list...)
}

func WriteString(in string) []byte {
	return WriteBytes([]byte(in))
}

func WriteAddress(in common.Address) []byte {
	return WriteBytes(in.Bytes())
}

func WriteUint(in uint256.Int) []byte {
	return WriteBytes(in.Bytes())
}

func writeBool(in bool) []byte {
	encoded := []byte{1}
	if !in {
		encoded[0] = 0x80
	}
	return encoded
}

// TODO: writeLength only supports lengths up to 2**256-1, while RLP
// supports 2^(2^(64-1)*8), e.g. very big.
func writeLength(length, offset uint64) []byte {
	if length < 56 {
		// Return only a single byte, offset + length.
		return []byte{byte(offset + length)}
	}
	// Return length of length (max 8 byte) and encoded length.
	// TODO: this function only supports uint64 right now.
	var (
		encoded          = make([]byte, 17, 17)
		lengthLen uint64 = 0
	)
	for i := uint64(0); (length / i) != 0; i = i * 256 {
		lengthLen += 1
	}
	encoded[0] = byte(offset + lengthLen)
	binary.BigEndian.PutUint64(encoded[1:9], lengthLen)
	binary.BigEndian.PutUint64(encoded[9:17], length)
	return encoded
}

func flatten(list [][]byte) []byte {
	if len(list) == 0 {
		return nil
	}
	flattened := make([]byte, 0, 512)
	for _, inner := range list {
		copy(flattened, inner)
	}
	return flattened
}
