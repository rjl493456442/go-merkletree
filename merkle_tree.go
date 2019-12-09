// Copyright 2019 Gary Rong
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"bytes"
	"errors"
	"fmt"
	"math"
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
	ErrUnknownEntry = errors.New("the entry is non-existent requested for proof")

	// ErrInvalidProof is returned if the provided merkle proof to verify is invalid.
	ErrInvalidProof = errors.New("invalid merkle proof")
)

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
	root, leaves, err := newTree(entries)
	if err != nil {
		return nil, err
	}
	return &MerkleTree{Root: root, Leaves: leaves}, nil
}

func newTree(entries []*Entry) (*Node, []*Node, error) {
	// Short circuit if we only have 1 entry, return it as the root node
	// of sub tree.
	if len(entries) == 1 {
		n := &Node{Value: entries[0]}
		return n, []*Node{n}, nil
	}
	var current *Node
	var leaves []*Node
	for i := 0; i < len(entries); {
		// Because all nodes are sorted in descending order of weight,
		// So the weight of first two nodes must be same and can be
		// grouped as a sub tree.
		if i == 0 {
			if entries[0].Weight() != entries[1].Weight() {
				return nil, nil, errors.New("invalid entries") // Should never happen
			}
			n1, n2 := &Node{Value: entries[0]}, &Node{Value: entries[1]}
			current = &Node{Left: n1, Right: n2}
			n1.Parent, n2.Parent = current, current
			i += 2
			leaves = append(leaves, n1, n2)
			continue
		}
		switch {
		case current.Weight() < entries[i].Weight():
			return nil, nil, errors.New("invalid entries") // Should never happen
		case current.Weight() == entries[i].Weight():
			n := &Node{Value: entries[i]}
			tmp := &Node{Left: current, Right: n}
			current.Parent, n.Parent = tmp, tmp
			current = tmp
			leaves = append(leaves, n)
			i += 1
		default:
			var j int
			var subsum float64
			for j = i; j < len(entries); j++ {
				subsum += entries[j].Weight()
				if subsum == current.Weight() {
					break
				}
			}
			right, subLeaves, err := newTree(entries[i : j+1])
			if err != nil {
				return nil, nil, err
			}
			tmp := &Node{Left: current, Right: right}
			current.Parent, right.Parent = tmp, tmp
			current = tmp
			leaves = append(leaves, subLeaves...)
			i += len(subLeaves)
		}
	}
	return current, leaves, nil
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
//
// Except returning the error indicates whether the proof is valid,
// this function will also return the "position" of entry which is
// proven.
//
// The merkle tree looks like:
//
//            e2     e3
//             \     /
//              \   /
//               \ /
//        e1     h2
//         \     /
//          \   /
//           \ /
//           h1     e4
//            \     /
//             \   /
//              \ /
//           root hash
//
// The position of the nodes is a range consisting of two points in
// a one-dimensional coordinate system ranging from 0 to 1. Like the
// position of e2 is [1/4, 3/8), the position of e3 is [3/8, 1/2).
func VerifyProof(root common.Hash, proof []common.Hash) (float64, float64, error) {
	if len(proof) == 0 {
		return 0, 0, ErrInvalidProof
	}
	if len(proof) == 1 {
		if root == proof[0] {
			return 0, 1, nil
		}
		return 0, 0, ErrInvalidProof
	}
	var (
		current = proof[0]
		pos     float64
	)
	for i := 1; i < len(proof); i += 1 {
		if bytes.Compare(current.Bytes(), proof[i].Bytes()) < 0 {
			current = crypto.Keccak256Hash(append(current.Bytes(), proof[i].Bytes()...))
		} else {
			pos = pos + math.Pow(2, float64(i-1))
			current = crypto.Keccak256Hash(append(proof[i].Bytes(), current.Bytes()...))
		}
	}
	if root != current {
		return 0, 0, ErrInvalidProof
	}
	return pos / math.Pow(2, float64(len(proof)-1)), (pos + 1) / math.Pow(2, float64(len(proof)-1)), nil
}

// String returns the string format of tree which helps to debug.
func (t *MerkleTree) String() string {
	return t.Root.String()
}
