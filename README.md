## Go-merkletree

This project implements a probability tree based on merkle tree structure. 

Users can pass a batch of entries with same or different value.  All entries will have an initial weight, which represents the probability that this node will be picked. Because the merkletree implemented in this package is a binary tree, the weight of entry can only support the form of 1/2 ^ n.

Merkletree will organize all passed entries, put they in different position which equals to the probability range they are specified.

### Install

`go get -u github.com/rjl493456442/go-merkletree`

### Example Usage

```go
func ExampleMerkleTree() {
	entry1 := &Entry{
		Value:       []byte{0x01,0x02},
		EntryWeight: 0.5,
	}
	entry2 := &Entry{
		Value:       []byte{0x03,0x04},
		EntryWeight: 0.25,
	}
	tree, err := NewMerkleTree([]*Entry{entry1, entry2})
	if err != nil {
		fmt.Println(err)
	}
	proof, err := tree.Prove(entry1)
	if err != nil {
		fmt.Println(err)
	}
	s, e, err := VerifyProof(tree.Hash(), proof)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(s, e)
	// Output: 0 0.5
}
```
