// Copyright (c) 2010 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz


package zdb

import (
	"bytes"
	"github.com/cznic/fileutil/falloc"
	"github.com/cznic/fileutil/storage"
	"os"
)

// Map is a reference to a hasmap in Store.
type Map struct {
	accessor storage.Accessor
	handle   falloc.Handle
	root     [8192]falloc.Handle
	store    *Store
}

// Get reads the value associated with key in m.
// It returns the data, key exists in ok and an os.Error, if any.
// Get returns non nil err iff !ok.
func (m *Map) Get(key []byte) (value []byte, ok bool, err os.Error) {
	defer func() {
		if e := recover(); e != nil {
			value, ok = nil, false
			err = e.(os.Error)
		}
	}()

	h := hash(key)

	// index ("vertical") search
	var hindex, hnode falloc.Handle
	if hindex = m.root[h>>13]; hindex == 0 { // key not found at index lvl 1
		return
	}

	if hnode = m.getIndex(hindex, h&h13); hnode == 0 { // key not found at index lvl 2
		return
	}

	if asserts && (hnode == 0) {
		panic("assert")
	}

	// "conflict" mode, node ("horizontal") search
	for hnode != 0 {
		var node []byte
		if node, err = m.store.Get(hnode); err != nil {
			panic(err)
		}

		var next, lens zip
		fp := next.get(node)
		fp += lens.get(node[fp:])
		if vp := fp + int(lens); int(lens) == len(key) && bytes.Equal(node[fp:vp], key) { // key found at node level
			return node[vp:], true, nil //TODO measure effects of copy()
		}

		hnode = falloc.Handle(next)
	}
	return // key not found at node level
}

func makeMapNode(next falloc.Handle, key, value []byte) (node []byte) {
	node = make([]byte, 8+2+len(key)+len(value))
	fp := zip(next).put2(node)
	fp += zip(len(key)).put2(node[fp:])
	fp += copy(node[fp:], key)
	fp += copy(node[fp:], value)
	return node[:fp]
}

func (m *Map) newMapIndex(at uint, handle falloc.Handle) (h falloc.Handle) {
	b := make([]byte, 8192*7)
	handle.Put(b[7*at:])
	var err os.Error
	if h, err = m.store.New(b); err != nil {
		panic(err)
	}
	return
}

func (m *Map) setIndex(x, h falloc.Handle, at uint) falloc.Handle {
	b := make([]byte, 7)
	h.Put(b)
	if _, err := m.accessor.WriteAt(b, int64(x)<<4+int64(7*at)+3); err != nil {
		panic(err)
	}

	return h
}

func (m *Map) getIndex(x falloc.Handle, at uint) (h falloc.Handle) {
	b := make([]byte, 7)
	if _, err := m.accessor.ReadAt(b, int64(x)<<4+int64(7*at)+3); err != nil {
		panic(err)
	}

	h.Get(b)
	return
}

// Set stores value under key in m and returns an os.Error if any.
func (m *Map) Set(key, value []byte) (err os.Error) {
	defer func() {
		if e := recover(); e != nil {
			err = e.(os.Error)
		}
	}()

	h := hash(key)

	// index ("vertical") search
	var hindex, hnode falloc.Handle
	if hindex = m.root[h>>13]; hindex == 0 { // key not found at index lvl 1
		if hnode, err = m.store.New(makeMapNode(0, key, value)); err != nil {
			return
		}

		hindex = m.newMapIndex(h&h13, hnode)
		m.root[h>>13] = m.setIndex(m.handle, hindex, h>>13)
		return
	}

	if hnode = m.getIndex(hindex, h&h13); hnode == 0 { // key not found at index lvl 2
		if hnode, err = m.store.New(makeMapNode(0, key, value)); err != nil {
			return
		}

		m.setIndex(hindex, hnode, h&h13)
		m.root[h>>13] = m.setIndex(m.handle, hindex, h>>13)
		return
	}

	if asserts && (hnode == 0) {
		panic("assert")
	}

	next := hnode

	// "conflict" mode, node ("horizontal") search
	for hnode != 0 {
		var node []byte
		if node, err = m.store.Get(hnode); err != nil {
			panic(err)
		}

		var next, lens zip
		fp := next.get(node)
		fp += lens.get(node[fp:])
		if vp := fp + int(lens); int(lens) == len(key) && bytes.Equal(node[fp:vp], key) { // key found at node level, "overwrite"
			//TODO reuse existing node in mem and its header?
			err = m.store.Set(hnode, makeMapNode(falloc.Handle(next), key, value))
			return
		}

		hnode = falloc.Handle(next)
	}
	//print("conflict")
	if hnode, err = m.store.New(makeMapNode(next, key, value)); err != nil {
		return
	}

	m.setIndex(hindex, hnode, h&h13)
	return
}

// Delete deletes the key from m and returns an os.Error if any.
func (m *Map) Delete(key string) (err os.Error) {
	defer func() {
		if e := recover(); e != nil {
			err = e.(os.Error)
		}
	}()

	panic("TODO")
	return
}

// Free destroys m and all of its key/value content.
// It returns an os.Error if any.
func (m *Map) Free() (err os.Error) {
	defer func() {
		if e := recover(); e != nil {
			err = e.(os.Error)
		}
	}()

	panic("TODO")
	return
}
