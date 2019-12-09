// Copyright 2019 Gary Rong
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

type merkleTreeTest struct {
	err     error
	entries []*Entry
}

func (t *merkleTreeTest) run() bool {
	tree, err := NewMerkleTree(t.entries)
	if err != nil {
		t.err = err
		return false
	}
	for _, entry := range t.entries {
		proof, err := tree.Prove(entry)
		if err != nil {
			t.err = err
			return false
		}
		if err := VerifyProof(tree.Root.Hash(), proof); err != nil {
			t.err = err
			return false
		}
	}
	return true
}

// Generate returns a new merkletree test of the given size. All randomness is
// derived from r.
func (*merkleTreeTest) Generate(r *rand.Rand, size int) reflect.Value {
	var (
		total   float64
		entries []*Entry
	)
	for total < 1 {
		remaining := 1 - total
		for i := 0; i < len(validWeights); i++ {
			if validWeights[i] <= remaining {
				index := r.Intn(len(validWeights)-i) + i
				value := make([]byte, 20)
				r.Read(value)
				entries = append(entries, &Entry{
					Value:       value,
					EntryWeight: validWeights[index],
				})
				total += validWeights[index]
				break
			}
		}
	}
	return reflect.ValueOf(&merkleTreeTest{entries: entries})
}

func (t *merkleTreeTest) String() string {
	var ret string
	for index, entry := range t.entries {
		ret += fmt.Sprintf("%d => (%f:%x)\n", index, entry.EntryWeight, entry.Value)
	}
	return ret
}

func TestMerkleTree(t *testing.T) {
	config := &quick.Config{MaxCount: 10000}
	err := quick.Check((*merkleTreeTest).run, config)
	if cerr, ok := err.(*quick.CheckError); ok {
		test := cerr.In[0].(*merkleTreeTest)
		t.Errorf("%v:\n%s", test.err, test)
	} else if err != nil {
		t.Error(err)
	}
}
