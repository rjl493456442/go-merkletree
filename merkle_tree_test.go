// Copyright 2019 Gary Rong
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"testing"
)

func TestBuilding(t *testing.T) {
	entries := []*Entry{
		{[]byte{0x01, 0x02}, 0.25},
		{[]byte{0x03, 0x04}, 0.125},
		{[]byte{0x05, 0x06}, 0.03125},
	}
	tree, err := NewMerkleTree(entries)
	if err != nil {
		t.Fatalf("Failed to build merkle tree: %v", err)
	}
	hashes, err := tree.Prove(entries[0])
	if err != nil {
		t.Fatalf("Failed to generate merkle proof: %v", err)
	}
	err = VerifyProof(tree.Root.Hash(), hashes)
	if err != nil {
		t.Fatalf("Failed to prove merkle proof: %v", err)
	}
}
