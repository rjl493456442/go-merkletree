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
	pos   uint64
	level uint64
}

// entryRanges implements the sort interface to allow sorting a list of entries
// range by the start point.
type entryRanges []entryRange

func (s entryRanges) Len() int { return len(s) }
func (s entryRanges) Less(i, j int) bool {
	d1, d2 := 1<<s[i].level, 1<<s[j].level
	return float64(s[i].pos)/float64(d1) < float64(s[j].pos)/float64(d2)
}
func (s entryRanges) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

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
		pos, err := VerifyProof(tree.Root.Hash(), proof)
		if err != nil {
			t.err = err
			return false
		}
		ranges = append(ranges, entryRange{pos, entry.Level})
	}
	sort.Sort(ranges)
	position := float64(0)
	for i := 0; i < len(ranges); i++ {
		d := 1 << ranges[i].level
		if float64(ranges[i].pos)/float64(d) != position {
			t.err = errors.New("invalid probability range")
			return false
		}
		position = float64(ranges[i].pos+1) / float64(d)
	}
	return true
}

// Generate returns a new merkletree test of the given size. All randomness is
// derived from r.
func (*merkleTreeTest) Generate(r *rand.Rand, size int) reflect.Value {
	var entries []*Entry
	length := r.Intn(30) + 1
	for i := 0; i < length; i++ {
		value := make([]byte, 20)
		r.Read(value)
		entries = append(entries, &Entry{
			Value:  value,
			Weight: uint64(r.Intn(30) + 1),
		})
	}
	return reflect.ValueOf(&merkleTreeTest{entries: entries})
}

func (t *merkleTreeTest) String() string {
	var ret string
	for index, entry := range t.entries {
		ret += fmt.Sprintf("%d => (%d:%x)\n", index, entry.Weight, entry.Value)
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
