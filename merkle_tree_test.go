// Copyright 2019 Gary Rong
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"testing"
	"testing/quick"
)

type merkleTreeTest struct {
	err     error
	entries []*Entry
}

type entryRange struct {
	start float64
	end   float64
}

// entryRanges implements the sort interface to allow sorting a list of entries
// range by the start point.
type entryRanges []entryRange

func (s entryRanges) Len() int           { return len(s) }
func (s entryRanges) Less(i, j int) bool { return s[i].start < s[j].start }
func (s entryRanges) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

func (t *merkleTreeTest) run() bool {
	tree, err := NewMerkleTree(t.entries)
	if err != nil {
		t.err = err
		return false
	}
	var ranges entryRanges
	for _, entry := range t.entries {
		proof, err := tree.Prove(entry)
		if err != nil {
			t.err = err
			return false
		}
		if s, e, err := VerifyProof(tree.Root.Hash(), proof); err != nil {
			t.err = err
			return false
		} else {
			ranges = append(ranges, entryRange{s, e})
		}
	}
	sort.Sort(ranges)
	position := float64(0)
	for i := 0; i < len(ranges); i++ {
		if ranges[i].start != position {
			t.err = errors.New("invalid probability range")
			return false
		}
		position = ranges[i].end
		if i == len(ranges)-1 {
			if position != float64(1) {
				t.err = fmt.Errorf("incomplete probability range, end:%f", position)
				return false
			}
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