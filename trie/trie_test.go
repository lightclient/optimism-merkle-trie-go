package trie

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

type test struct {
	name string
	kv   [][]string
	root string
}

type proofList [][]byte

func (n *proofList) Put(key []byte, value []byte) error {
	*n = append(*n, value)
	return nil
}

func (n *proofList) Delete(key []byte) error {
	panic("not supported")
}

func TestTrie(t *testing.T) {
	tests := []test{
		{
			name: "empty values",
			kv: [][]string{
				{"do", "verb"},
				{"ether", "wookiedoo"},
				{"horse", "stallion"},
				{"shaman", "horse"},
				{"doge", "coin"},
				{"ether", ""},
				{"dog", "puppy"},
				{"shaman", ""},
			},
			root: "0x5991bb8c6514148a29db676a14ac506cd2cd5775ace63c30a4fe457715e9ac84",
		},
		{
			name: "branching tests",
			kv: [][]string{
				{"0x04110d816c380812a427968ece99b1c963dfbce6", "something"},
				{"0x095e7baea6a6c7c4c2dfeb977efac326af552d87", "something"},
				{"0x0a517d755cebbf66312b30fff713666a9cb917e0", "something"},
				{"0x24dd378f51adc67a50e339e8031fe9bd4aafab36", "something"},
				{"0x293f982d000532a7861ab122bdc4bbfd26bf9030", "something"},
				{"0x2cf5732f017b0cf1b1f13a1478e10239716bf6b5", "something"},
				{"0x31c640b92c21a1f1465c91070b4b3b4d6854195f", "something"},
				{"0x37f998764813b136ddf5a754f34063fd03065e36", "something"},
				{"0x37fa399a749c121f8a15ce77e3d9f9bec8020d7a", "something"},
				{"0x4f36659fa632310b6ec438dea4085b522a2dd077", "something"},
				{"0x62c01474f089b07dae603491675dc5b5748f7049", "something"},
				{"0x729af7294be595a0efd7d891c9e51f89c07950c7", "something"},
				{"0x83e3e5a16d3b696a0314b30b2534804dd5e11197", "something"},
				{"0x8703df2417e0d7c59d063caa9583cb10a4d20532", "something"},
				{"0x8dffcd74e5b5923512916c6a64b502689cfa65e1", "something"},
				{"0x95a4d7cccb5204733874fa87285a176fe1e9e240", "something"},
				{"0x99b2fcba8120bedd048fe79f5262a6690ed38c39", "something"},
				{"0xa4202b8b8afd5354e3e40a219bdc17f6001bf2cf", "something"},
				{"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b", "something"},
				{"0xa9647f4a0a14042d91dc33c0328030a7157c93ae", "something"},
				{"0xaa6cffe5185732689c18f37a7f86170cb7304c2a", "something"},
				{"0xaae4a2e3c51c04606dcb3723456e58f3ed214f45", "something"},
				{"0xc37a43e940dfb5baf581a0b82b351d48305fc885", "something"},
				{"0xd2571607e241ecf590ed94b12d87c94babe36db6", "something"},
				{"0xf735071cbee190d76b704ce68384fc21e389fbe7", "something"},
				{"0x04110d816c380812a427968ece99b1c963dfbce6", ""},
				{"0x095e7baea6a6c7c4c2dfeb977efac326af552d87", ""},
				{"0x0a517d755cebbf66312b30fff713666a9cb917e0", ""},
				{"0x24dd378f51adc67a50e339e8031fe9bd4aafab36", ""},
				{"0x293f982d000532a7861ab122bdc4bbfd26bf9030", ""},
				{"0x2cf5732f017b0cf1b1f13a1478e10239716bf6b5", ""},
				{"0x31c640b92c21a1f1465c91070b4b3b4d6854195f", ""},
				{"0x37f998764813b136ddf5a754f34063fd03065e36", ""},
				{"0x37fa399a749c121f8a15ce77e3d9f9bec8020d7a", ""},
				{"0x4f36659fa632310b6ec438dea4085b522a2dd077", ""},
				{"0x62c01474f089b07dae603491675dc5b5748f7049", ""},
				{"0x729af7294be595a0efd7d891c9e51f89c07950c7", ""},
				{"0x83e3e5a16d3b696a0314b30b2534804dd5e11197", ""},
				{"0x8703df2417e0d7c59d063caa9583cb10a4d20532", ""},
				{"0x8dffcd74e5b5923512916c6a64b502689cfa65e1", ""},
				{"0x95a4d7cccb5204733874fa87285a176fe1e9e240", ""},
				{"0x99b2fcba8120bedd048fe79f5262a6690ed38c39", ""},
				{"0xa4202b8b8afd5354e3e40a219bdc17f6001bf2cf", ""},
				{"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b", ""},
				{"0xa9647f4a0a14042d91dc33c0328030a7157c93ae", ""},
				{"0xaa6cffe5185732689c18f37a7f86170cb7304c2a", ""},
				{"0xaae4a2e3c51c04606dcb3723456e58f3ed214f45", ""},
				{"0xc37a43e940dfb5baf581a0b82b351d48305fc885", ""},
				{"0xd2571607e241ecf590ed94b12d87c94babe36db6", ""},
				{"0xf735071cbee190d76b704ce68384fc21e389fbe7", ""},
			},
			root: "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
		},
		{
			name: "jeff",
			kv: [][]string{
				{"0x0000000000000000000000000000000000000000000000000000000000000045", "0x22b224a1420a802ab51d326e29fa98e34c4f24ea"},
				{"0x0000000000000000000000000000000000000000000000000000000000000046", "0x67706c2076330000000000000000000000000000000000000000000000000000"},
				{"0x0000000000000000000000000000000000000000000000000000001234567890", "0x697c7b8c961b56f675d570498424ac8de1a918f6"},
				{"0x000000000000000000000000697c7b8c961b56f675d570498424ac8de1a918f6", "0x1234567890"},
				{"0x0000000000000000000000007ef9e639e2733cb34e4dfc576d4b23f72db776b2", "0x4655474156000000000000000000000000000000000000000000000000000000"},
				{"0x000000000000000000000000ec4f34c97e43fbb2816cfd95e388353c7181dab1", "0x4e616d6552656700000000000000000000000000000000000000000000000000"},
				{"0x4655474156000000000000000000000000000000000000000000000000000000", "0x7ef9e639e2733cb34e4dfc576d4b23f72db776b2"},
				{"0x4e616d6552656700000000000000000000000000000000000000000000000000", "0xec4f34c97e43fbb2816cfd95e388353c7181dab1"},
				{"0x0000000000000000000000000000000000000000000000000000001234567890", ""},
				{"0x000000000000000000000000697c7b8c961b56f675d570498424ac8de1a918f6", "0x6f6f6f6820736f2067726561742c207265616c6c6c793f000000000000000000"},
				{"0x6f6f6f6820736f2067726561742c207265616c6c6c793f000000000000000000", "0x697c7b8c961b56f675d570498424ac8de1a918f6"},
			},
			root: "0x9f6221ebb8efe7cff60a716ecb886e67dd042014be444669f0159d8e68b42100",
		},
		{
			name: "insert-middle-leaf",
			kv: [][]string{
				{"key1aa", "0123456789012345678901234567890123456789xxx"},
				{"key1", "0123456789012345678901234567890123456789Very_Long"},
				{"key2bb", "aval3"},
				{"key2", "short"},
				{"key3cc", "aval3"},
				{"key3", "1234567890123456789012345678901"},
			},
			root: "0xcb65032e2f76c48b82b5c24b3db8f670ce73982869d38cd39a624f23d62a9e89",
		},
		{
			name: "branch-value-update",
			kv: [][]string{
				{"abc", "123"},
				{"abcd", "abcd"},
				{"abc", "abc"},
			},
			root: "0x7a320748f780ad9ad5b0837302075ce0eeba6c26e3d8562c67ccc0f1b273298a",
		},
	}
	for _, test := range tests {
		trie, _ := trie.New(common.Hash{}, trie.NewDatabase(memorydb.New()))
		for _, kv := range test.kv {
			trie.Update(hexToBytes(kv[0]), hexToBytes(kv[1]))
		}
		got := trie.Hash()
		if got != common.HexToHash(test.root) {
			t.Fatalf("root mismatch: got %s, want %s", got, test.root)
		}
		iter := trie.NodeIterator(nil)
		for iter.Next(false) {
			defer func() {
				if err := recover(); err != nil {
					t.Fatalf("%s: panic occurred: %s", test.name, err)
				}
			}()
			if !iter.Leaf() {
				continue
			}
			k := iter.LeafKey()
			v := iter.LeafBlob()
			proof := iter.LeafProof()
			flat, err := rlp.EncodeToBytes(proof)
			if err != nil {
				t.Fatalf("unable to encode proof: %s", err)
			}
			success := VerifyInclusionProof(k, v, flat, trie.Hash())
			if !success {
				t.Fatalf("failed to verify key-value (%s, %s) for %s\n", k, v, test.name)
			}
		}
	}

}

func hexToBytes(hex string) []byte {
	if strings.HasPrefix(hex, "0x") {
		return common.Hex2Bytes(hex[2:])
	}
	return []byte(hex)
}
