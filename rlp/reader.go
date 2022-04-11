package rlp

import (
	"encoding/binary"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

const MAX_LIST_LENGTH = 32
const SHORT_STRING_PREFIX = 0x80

type RLPItemType int

const (
	DataItem RLPItemType = iota
	ListItem
)

type RLPItem struct {
	Length uint64
	ptr    []byte
}

func ToRLPLItem(bytes []byte) RLPItem {
	return RLPItem{
		Length: uint64(len(bytes)),
		ptr:    bytes,
	}
}

func ReadList(in RLPItem) []RLPItem {
	offset, _, itemType := decodeLength(in)
	if itemType != ListItem {
		panic("attempting to read list on non-list input")
	}
	var (
		out       []RLPItem
		itemCount = 0
	)
	for {
		if itemCount == MAX_LIST_LENGTH {
			panic("list exceeds max item length")
		}
		itemOffset, itemLength, _ := decodeLength(RLPItem{
			Length: in.Length - offset,
			ptr:    in.ptr[offset:],
		})
		out = append(out, RLPItem{Length: itemLength, ptr: in.ptr[offset:]})
		itemCount += 1
		offset += itemOffset + itemLength
		if offset >= in.Length {
			break
		}
	}
	return out
}

func ReadListBytes(in []byte) []RLPItem {
	return ReadList(ToRLPLItem(in))
}

func ReadBytes(in RLPItem) []byte {
	itemOffset, itemLength, itemType := decodeLength(in)
	if itemType != DataItem {
		panic("expected RLP string")
	}
	// TODO: does this need to be copied?
	return in.ptr[itemOffset : itemOffset+itemLength]
}

func ReadBytesBytes(in []byte) []byte {
	return ReadBytes(ToRLPLItem(in))
}

func ReadString(in RLPItem) string {
	return string(ReadBytes(in))
}

func ReadStringBytes(in []byte) string {
	return string(ReadBytes(ToRLPLItem(in)))
}

func ReadBytes32(in RLPItem) common.Hash {
	if in.Length > 32 {
		panic("invalid bytes32 value")
	}
	itemOffset, itemLength, itemType := decodeLength(in)
	if itemType != DataItem {
		panic("expected data item, got list")
	}
	return common.BytesToHash(in.ptr[itemOffset : itemOffset+itemLength])
}

func ReadBytes32Bytes(in []byte) common.Hash {
	return ReadBytes32(ToRLPLItem(in))
}

func ReadUint256(in RLPItem) *uint256.Int {
	ret, _ := uint256.FromBig(ReadBytes32(in).Big())
	return ret
}

func ReadUint256Bytes(in []byte) *uint256.Int {
	return ReadUint256(ToRLPLItem(in))
}

func ReadBool(in RLPItem) bool {
	if in.Length != 1 {
		panic("invalid bool value")
	}
	out := in.ptr[0]
	if out != 0 && out != 1 {
		panic("invalid bool value, must be 0 or 1")
	}
	return out != 0
}

func ReadBoolBytes(in []byte) bool {
	return ReadBool(ToRLPLItem(in))
}

func ReadAddress(in RLPItem) common.Address {
	// TODO: what is the deal with this?
	if in.Length == 1 {
		return common.Address{}
	}
	if in.Length != 21 {
		panic("invalid address value")
	}
	return common.BytesToAddress(ReadBytes(in))
}

func ReadAddressBytes(in []byte) common.Address {
	return ReadAddress(ToRLPLItem(in))
}

func ReadRawBytes(in RLPItem) []byte {
	return in.ptr
}

// decodeLength takes an RLPItem and returns the offset of the encoded
// data, the length of the encoded data, and the RLPItemType.
func decodeLength(in RLPItem) (uint64, uint64, RLPItemType) {
	if in.Length == 0 {
		panic("RLP item cannot be null")
	}
	prefix := in.ptr[0]
	switch {
	case prefix <= 0x7f:
		// Single byte.
		return 0, 1, DataItem
	case prefix <= 0xb7:
		// Short string.
		strLen := uint64(prefix - 0x80)
		if in.Length < strLen {
			panic("expected string length exceeds actual")
		}
		return 1, strLen, DataItem
	case prefix <= 0xbf:
		// Long string.
		lenOfStrLen := uint64(prefix - 0xb7)
		if in.Length < lenOfStrLen {
			panic("expected length of string length exceeds actual")
		}
		strLen := binary.BigEndian.Uint64(in.ptr[1:lenOfStrLen])
		if in.Length < lenOfStrLen+strLen {
			panic("expected string length exceeds actual")
		}
		return 1 + lenOfStrLen, strLen, DataItem
	case prefix <= 0xf7:
		// Short list.
		listLen := uint64(prefix - 0xc0)
		if in.Length < listLen {
			panic("expected list length exceeds actual")
		}
		return 1, listLen, ListItem
	default:
		// Long list
		lenOfListLen := uint64(prefix - 0xb7)
		if in.Length > lenOfListLen {
			panic("expected length of list length exceeds actual")
		}
		listLen := binary.BigEndian.Uint64(in.ptr[1:lenOfListLen])
		if in.Length < lenOfListLen+listLen {
			panic("expected list length exceeds actual")
		}
		return 1 + lenOfListLen, listLen, DataItem
	}
}
