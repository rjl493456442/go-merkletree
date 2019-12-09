// Copyright 2019 Gary Rong
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	// validWeights includes all valid/supported entry weight.
	//
	// The minimal weight supported is 1/1024.
	validWeights = []float64{1, 0.5, 0.25, 0.125, 0.0625, 0.03125, 0.015625, 0.0078125, 0.00390625, 0.001953125, 0.0009765625}

	// validWeightFlag is the mapping format of validWeights.
	validWeightsFlag = make(map[float64]bool)
)

func init() {
	for _, w := range validWeights {
		validWeightsFlag[w] = true
	}
}

var (
	// ErrWeightSumOverflow is returned if the total weight of given entries
	// exceeds 1.
	ErrWeightSumOverflow = errors.New("the cumulative weight of entries overflow")

	// ErrInvalidWeight is returned if the weight of entry doesn't obey 1/2^N form.
	ErrInvalidWeight = errors.New("invalid entry weight")

	// ErrUnknownEntry is returned if caller wants to prove an non-existent entry.
	ErrUnknownEntry = errors.New("the entry is non-existent to tree which is requested for proof")

	// ErrInvalidProof is returned if the provided merkle proof to verify is invalid.
	ErrInvalidProof = errors.New("invalid merkle proof")
)

// node represents a merkle tree node or a data entry referenced by the merkle tree.
type node interface {
	// Hash returns the hash of data entry.
	Hash() common.Hash

	// Weight returns the weight of data entry. Note The weight value
	// must be of the form 1/2 ^ N.
	Weight() float64
}

// Entry represents the data entry referenced by the merkle tree.
type Entry struct {
	Value       []byte
	EntryWeight float64
}

func (s *Entry) Hash() common.Hash { return crypto.Keccak256Hash(s.Value) }
func (s *Entry) Weight() float64   { return s.EntryWeight }

// EntryByWeight implements the sort interface to allow sorting a list of entries
// by their weight.
type EntryByWeight []*Entry

func (s EntryByWeight) Len() int           { return len(s) }
func (s EntryByWeight) Less(i, j int) bool { return s[i].EntryWeight < s[j].EntryWeight }
func (s EntryByWeight) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// Node represents a node in merkle tree.
type Node struct {
	Nodehash common.Hash // The hash of node.
	Parent   *Node       // The parent of this node, nil if it's root node.
	Left     *Node       // The left child of this node
	Right    *Node       // The right child of this node
	Value    *Entry      // The referenced entry by this node, nil if it's not leaf.
}

// Hash returns the hash of this tree node.
func (node *Node) Hash() common.Hash {
	// Short circuit if nodehash is already cached.
	if node.Nodehash != (common.Hash{}) {
		return node.Nodehash
	}
	// If it's a leaf node, derive the hash by the entry content.
	if node.Value != nil {
		node.Nodehash = node.Value.Hash()
		return node.Nodehash
	}
	// It's a branch node, derive the hash via two children.
	leaf, right := node.Left.Hash(), node.Right.Hash() // Both children should never be nil.
	if bytes.Compare(leaf.Bytes(), right.Bytes()) < 0 {
		node.Nodehash = crypto.Keccak256Hash(append(leaf.Bytes(), right.Bytes()...))
	} else {
		node.Nodehash = crypto.Keccak256Hash(append(right.Bytes(), leaf.Bytes()...))
	}
	return node.Nodehash
}

// Weight returns the weight of this tree node.
func (node *Node) Weight() float64 {
	if node.Value != nil {
		return node.Value.Weight()
	}
	return node.Left.Weight() + node.Right.Weight()
}

// String returns the string format of node.
func (node *Node) String() string {
	if node.Value != nil {
		value := hexutil.Encode(node.Value.Value)
		if node.Value.Value == nil {
			value = "null"
		}
		return fmt.Sprintf("E(%s:%f)", value, node.Value.EntryWeight)
	}
	return fmt.Sprintf("N(%x) => L.(%s) R.(%s)", node.Hash(), node.Left.String(), node.Right.String())
}

type MerkleTree struct {
	Roothash common.Hash // The hash of root node, maybe null if we never calculate it.
	Root     *Node       // The root node of merkle tree.
	Leaves   []*Node     // Batch of leaves node included in the tree.
}

func NewMerkleTree(entries []*Entry) (*MerkleTree, error) {
	// Verify the validity of the given entries.
	var sum float64
	for _, entry := range entries {
		weight := entry.Weight()
		if !validWeightsFlag[weight] {
			return nil, ErrInvalidWeight
		}
		sum += weight
	}
	if sum > 1 {
		return nil, ErrWeightSumOverflow
	}
	// Fill null entry if we can't form a completed merkle tree.
	missing := 1 - sum
	for missing > 0 {
		for i := 0; i < len(validWeights); i++ {
			if missing >= validWeights[i] {
				// Full empty data entry in order to form a completed tree.
				entries = append(entries, &Entry{EntryWeight: validWeights[i]})
				missing -= validWeights[i]
				break
			}
		}
	}
	// Sort them based on the weight in ascending order.
	sort.Sort(EntryByWeight(entries))

	// Start to build the merkle tree, short circuit if there is only 1 entry.
	if len(entries) == 1 {
		return &MerkleTree{Root: &Node{Value: entries[0]}}, nil
	}
	var current *Node
	var leaves []*Node
	for i := 0; i < len(entries); {
		if i == 0 {
			n1, n2 := &Node{Value: entries[0]}, &Node{Value: entries[1]}
			current = &Node{Left: n1, Right: n2}
			n1.Parent, n2.Parent = current, current
			i += 2
			leaves = append(leaves, n1, n2)
			continue
		}
		if current.Weight() < entries[i].Weight() {
			return nil, errors.New("invalid entry order")
		} else if current.Weight() == entries[i].Weight() {
			n := &Node{Value: entries[i]}
			tmp := &Node{Left: current, Right: n}
			current.Parent, n.Parent = tmp, tmp
			current = tmp
			leaves = append(leaves, n)
			i += 1
		} else {
			if len(entries)-i < 2 {
				return nil, errors.New("incomplete tree")
			}
			n1, n2 := &Node{Value: entries[i]}, &Node{Value: entries[i+1]}
			right := &Node{Left: n1, Right: n2}
			n1.Parent, n2.Parent = right, right
			tmp := &Node{Left: current, Right: right}
			current.Parent, right.Parent = tmp, tmp
			current = tmp
			i += 2
			leaves = append(leaves, n1, n2)
		}
	}
	return &MerkleTree{Root: current, Leaves: leaves}, nil
}

// Hash calculates the root hash of merkle tree.
func (t *MerkleTree) Hash() common.Hash {
	return t.Root.Hash()
}

// Prove constructs a merkle proof for the specified entry.
func (t *MerkleTree) Prove(e *Entry) ([]common.Hash, error) {
	var n *Node
	for _, leaf := range t.Leaves {
		if leaf.Value == e {
			n = leaf
		}
	}
	if n == nil {
		return nil, ErrUnknownEntry
	}
	var hashes []common.Hash
	hashes = append(hashes, n.Hash())
	for {
		if n.Parent == nil {
			break
		}
		if n.Parent.Left == n {
			hashes = append(hashes, n.Parent.Right.Hash())
		} else {
			hashes = append(hashes, n.Parent.Left.Hash())
		}
		n = n.Parent
	}
	return hashes, nil
}

// VerifyProof verifies the provided merkle proof is valid or not.
func VerifyProof(root common.Hash, hashes []common.Hash) error {
	if len(hashes) == 0 {
		return ErrInvalidProof
	}
	if len(hashes) == 1 {
		if root == hashes[0] {
			return nil
		}
		return ErrInvalidProof
	}
	current := hashes[0]
	for i := 1; i < len(hashes); i += 1 {
		if bytes.Compare(current.Bytes(), hashes[i].Bytes()) < 0 {
			current = crypto.Keccak256Hash(append(current.Bytes(), hashes[i].Bytes()...))
		} else {
			current = crypto.Keccak256Hash(append(hashes[i].Bytes(), current.Bytes()...))
		}
	}
	if root != current {
		return ErrInvalidProof
	}
	return nil
}

// String returns the string format of tree which helps to debug.
func (t *MerkleTree) String() string {
	return t.Root.String()
}
