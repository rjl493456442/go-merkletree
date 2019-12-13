## Go-merkletree

This project implements a probability tree based on merkle tree structure. 

Users can pass a batch of entries with same or different value.  All entries will have an initial weight, which represents the probability that this node will be picked. Because the merkletree implemented in this package is a binary tree, so the final weight of each entry will be adjusted to 1/2^N format.

Merkletree will organize all passed entries, put they in different position which equals to the probability range they are specified.

### Install

`go get -u github.com/rjl493456442/go-merkletree`

### Example Usage

```go
func ExampleMerkleTree() {
    entry1 := &Entry{
		Value:  []byte{0x01, 0x02},
		Weight: 2,
	}
	entry2 := &Entry{
		Value:  []byte{0x03, 0x04},
		Weight: 1,
	}
	entry3 := &Entry{
		Value:  []byte{0x05, 0x06},
		Weight: 1,
	}
	tree, err := NewMerkleTree([]*Entry{entry1, entry2, entry3})
	if err != nil {
		fmt.Println(err)
	}
	proof, err := tree.Prove(entry1)
	if err != nil {
		fmt.Println(err)
	}
	pos, err := VerifyProof(tree.Hash(), proof)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(pos)
	// Output: 0
}
```
