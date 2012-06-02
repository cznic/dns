// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

package dns

import (
	"strings"
	"sync"
)

// GoTree is a concurrent access safe version of Tree.
type GoTree struct {
	tree *Tree
	rwm  sync.RWMutex
}

// NewGoTree returns a newly created GoTree.
func NewGoTree() *GoTree {
	return &GoTree{tree: NewTree()}
}

// Add will add data to GoTree. If the owner node has no data yet, the data
// will be simply inserted in that node. If the updater is not nil and the
// owner node already has some existing data then the value returned by
// updater(existing_data) is inserted into the owner node.
func (t *GoTree) Add(owner string, data interface{}, updater func(interface{}) interface{}) {
	t.rwm.Lock()
	defer t.rwm.Unlock()
	t.tree.Add(owner, data, updater)
}

// Delete deletes data associated with owner, if any.
func (t *GoTree) Delete(owner string) {
	t.rwm.Lock()
	defer t.rwm.Unlock()
	t.tree.Put(owner, nil)
}

// Enum enumerates all data in the tree starting at root and all of its childs.
// On every datum found the handler is invoked.  If the handler returns false
// the tree traversing stops.
func (t *GoTree) Enum(root string, handler func(path []string, data interface{}) bool) {
	t.rwm.RLock()
	defer t.rwm.RUnlock()
	t.tree.Enum(root, handler)
}

// Get returns the data associated with owner or nil if there are none.
func (t *GoTree) Get(owner string) interface{} {
	t.rwm.RLock()
	defer t.rwm.RUnlock()
	return t.tree.Get(owner)
}

// Match returns the data associated with the largest part of owner or nil if
// there are none. See also Tree.Match for details.
func (t *GoTree) Match(owner string) interface{} {
	t.rwm.RLock()
	defer t.rwm.RUnlock()
	return t.tree.Match(owner)
}

// Put will put data to Tree. If the owner node already has some existing data
// they will be overwritten by the new data.
func (t *GoTree) Put(owner string, data interface{}) {
	t.rwm.Lock()
	defer t.rwm.Unlock()
	t.tree.Add(owner, data, nil)
}

type indexnode map[string]interface{}

type mixednode struct {
	indexnode
	data interface{}
}

// Tree implements a hierarchical tree of any data (interface{}). The hierarchy
// is based on case insensitive labels of a rooted domain name.  Tree is *not*
// concurrent access safe.
type Tree struct {
	root interface{}
}

// NewTree returns a newly created Tree.
func NewTree() *Tree {
	return &Tree{indexnode(map[string]interface{}{})}
}

// Delete deletes data associated with owner, if any.
func (t *Tree) Delete(owner string) {
	t.Put(owner, nil)
}

func enum(path []string, node interface{}, handler func(path []string, data interface{}) bool) bool {
	switch x := node.(type) {
	case indexnode:
		for label, ch := range x {
			if !enum(append(path, label), ch, handler) {
				return false
			}
		}
	case mixednode:
		if !handler(path, x.data) {
			return false
		}
		for label, ch := range x.indexnode {
			if !enum(append(path, label), ch, handler) {
				return false
			}
		}
	default:
		if !handler(path, x) {
			return false
		}
	}
	return true
}

// Enum enumerates all data in the tree starting at root and all of its childs.
// On every datum found the handler is invoked.  If the handler returns false
// the tree traversing stops.
func (t *Tree) Enum(root string, handler func(path []string, data interface{}) bool) {
	path, node, _ := t.getnode(root)
	enum(path, node, handler)
}

func (t *Tree) getnode(owner string) (path []string, node, match interface{}) {
	path = namev(owner)
	this := t.root
	for _, label := range path {
		switch x := this.(type) {
		case indexnode:
			var ok bool
			if this, ok = x[label]; !ok {
				return
			}

		case mixednode:
			var ok bool
			match = x.data
			if this, ok = x.indexnode[label]; !ok {
				return
			}

		default:
			match = this
			return
		}

	}
	node = this
	return
}

// Get returns the data associated with owner or nil if there are none.
func (t *Tree) Get(owner string) interface{} {
	_, node, _ := t.getnode(owner)
	switch x := node.(type) {
	case indexnode:
		return nil
	case mixednode:
		return x.data
	default:
		return x
	}
	panic("unreachable")
}

// Match returns the data associated with the largest part of owner or nil if
// there are none.
//
// If the tree "map" contains
//  "www.example.com.": "www-example-com"
//  "example.org.": "www-example-org"
// then
//  t.Match(".") == nil
//  t.Match("com.") == nil
//  t.Match("example.com.") == nil
//  t.Match("www.example.com.") == "www-example-com"
//  t.Match("ns.www.example.com.") == "www-example-com"
//  t.Match("org.") == nil
//  t.Match("example.org.") == "www-example-org"
//  t.Match("www.example.org.") == "www-example-org"
//
// In other words, Match returns the most recent (last seen) data item present
// in the tree when walking the DNS name hiearchy.
func (t *Tree) Match(owner string) interface{} {
	_, node, match := t.getnode(owner)
	switch x := node.(type) {
	case indexnode:
		return match
	case mixednode:
		return x.data
	default:
		if node != nil {
			return node
		}

		return match
	}
	panic("unreachable")
}

// Add will add data to Tree. If the owner node has no data yet, the data will
// be simply inserted in that node. If the updater is not nil and the owner
// node already has some existing data then the value returned by
// updater(existing_data) is inserted into the owner node.
func (t *Tree) Add(owner string, data interface{}, updater func(interface{}) interface{}) {
	nv := namev(owner)
	n := len(nv)
	this := t.root
	for i, label := range nv {
		switch node := this.(type) {
		case indexnode:
			if next, ok := node[label]; ok {
				if i+1 == n {
					switch x := next.(type) {
					case indexnode:
						node[label] = mixednode{x, data}
					case mixednode:
						if updater == nil {
							x.data = data // overwrite
						} else {
							x.data = updater(x.data) // update
						}
						node[label] = x
					default: // data node
						if updater == nil {
							node[label] = data // overwrite
						} else {
							node[label] = updater(x) // update
						}
					}
				} else {
					switch x := next.(type) {
					case indexnode:
						this = x
					case mixednode:
						this = x.indexnode
					default: // data node
						next = mixednode{map[string]interface{}{}, x}
						node[label] = next
						this = next
					}
				}
			} else {
				if i+1 == n {
					node[label] = data
				} else {
					next = indexnode(map[string]interface{}{})
					node[label] = next
					this = next
				}
			}
		case mixednode:
			//if _, ok := node.indexnode[label]; ok {
			//panic("dns.Tree.Put() internal error 2")
			//} else {
			if i+1 == n {
				node.indexnode[label] = data
			} else {
				next := indexnode(map[string]interface{}{})
				node.indexnode[label] = next
				this = next
			}
			//}
		default:
			panic("dns.Tree.Add() internal error")
		}
	}
}

// Put will put data to Tree. If the owner node already has some existing data
// they will be overwritten by the new data.
func (t *Tree) Put(owner string, data interface{}) {
	t.Add(owner, data, nil)
}

func namev(name string) (y []string) {
	labels, _ := Labels(name)
	n := len(labels)
	y = make([]string, n)
	for _, label := range labels {
		n--
		y[n] = strings.ToLower(label)
	}
	return
}
