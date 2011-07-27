// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz


package rr

import (
	"github.com/cznic/dns"
)

// Tree "subclasses" the dns.Tree methods for the RRs type.
type Tree dns.Tree

// NewTree returns a newly created Tree.
func NewTree() *Tree {
	return (*Tree)(dns.NewTree())
}

// Add will add data to Tree. If the owner node has no data yet, the data will be simply inserted in that node.
// If the updater is not nil and the owner node already has some existing data then the value
// returned by updater(existing_data) is inserted into the owner node.
func (t *Tree) Add(owner string, data RRs, updater func(RRs) RRs) {
	(*dns.Tree)(t).Add(owner, data.Pack(), func(existing interface{}) interface{} {
		return updater(existing.(Bytes).Unpack()).Pack()
	})
}

// Delete deletes data associated with owner, if any.
func (t *Tree) Delete(owner string) {
	(*dns.Tree)(t).Delete(owner)
}

// Enum enumerates all data in the tree starting at root and all of it's childs.
// On every datum found the handler is invoked. If the handler returns false the tree traversing stops.
func (t *Tree) Enum(root string, handler func(path []string, data RRs) bool) {
	(*dns.Tree)(t).Enum(root, func(path []string, data interface{}) bool {
		switch x := data.(type) {
		case nil:
			return handler(path, nil)
		default:
			return handler(path, data.(Bytes).Unpack())
		}
		panic("unreachable")
	})
}

// Get returns the data associated with owner or nil if there are none.
func (t *Tree) Get(owner string) (y RRs) {
	iface := (*dns.Tree)(t).Get(owner)
	if iface != nil {
		y = iface.(Bytes).Unpack()
	}
	return
}

// Put will put data to Tree. If the owner node already has some existing data they will be overwritten by the new data.
func (t *Tree) Put(owner string, data RRs) {
	(*dns.Tree)(t).Put(owner, data.Pack())
}
