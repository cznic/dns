// Copyright (c) 2010 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

// WIP: Package zdb provides a specialized DB engine for DNS zone(s)/a DNS server, i.e. some design parameters/decisions
// were made with the expected usage in mind wrt the forementioned usage patterns/clients.
// E.g. currently a single map key hash is 26 bit only (=> max 64M buckets), as the expected maximum number
// of distinct domain names in a single zone is estimated to be bellow 100M (and in an order of magnitudes
// less on average).
//
// This combined with a theoretically sound hash algorithm (FNV-1a) leads to an estimatedly acceptable,
// low enough collision rate, even with such short hash keys.
//
// The paybayck is the ability to have hash indexes in only two levels 
// (the limit for a simple falloc []byte content object is about 60kB and the DB "pointers" are 7 bytes).
//
// The first index level is always fully cached, so a non colliding map access reaches the key value
// on the second "disk" accesses (the first is for the level 2 [leaf] hash index).
//
// This is guessed to be fast enough to make the DNS server still perform within tolerable
// latency times on nowadays server grade HW (and it will get only better with the raise of SSD
// and simillar/better future "HD like" technologies).
//
// Note that the mentioned latency has (mostly) nothing to do with the server's QPS throughput.
//
// This is ATM a WIP, the real numbers will be known only after benchmarks.
package zdb

import (
	"github.com/cznic/fileutil/falloc"
	"github.com/cznic/fileutil/hdb"
	"github.com/cznic/fileutil/storage"
	"log"
	"os"
)

const asserts = true

func init() {
	log.SetFlags(log.Flags() | log.Lshortfile)
	if asserts {
		log.Print("assertions enabled")
	}
}

// Store is a DNS zone(s)/DNS server DB.
//
// Any object ([]byte) can be used as the DB root.
//
// If convenient then a ready to use Map can be used via the RootMap field.
// This can not be mixed with other root objects. For a non map root it is assumed
// that the root somehow stores/references handles to other used map(s).
// In any case, Store can mix (use simultaneously) Map data (string key/value) and hdb.Store handle/value data.
//
// The underlying hdb.Store is accessible as the Store field of Store.
// Additionaly the hdb.Store methods are emebeded into the Store method set.
type Store struct {
	*hdb.Store
	RootMap  *Map // Ready to use root map or nil
	accessor storage.Accessor
}

// New creates the Store in 'store', truncating it if it already exists.
// If rootMap then a new Map is created, the falloc.File root is made pointing to it and it is assigned to store.RootMap.
// If successful, methods on the returned Store can be used for I/O. It returns the store and an os.Error, if any.
func New(store storage.Accessor, rootMap bool) (s *Store, err os.Error) {
	s = &Store{}

	defer func() {
		if e := recover(); e != nil {
			s = nil
			err = e.(os.Error)
		}
	}()

	if s.Store, err = hdb.New(store); err != nil {
		panic(err)
	}

	s.accessor = s.Store.File().Accessor()

	if !rootMap {
		return
	}

	s.RootMap = &Map{accessor: s.accessor, store: s}
	if err = s.Set(s.Root(), make([]byte, 8192*7)); err != nil {
		panic(err)
	}

	b := make([]byte, 8)
	if _, err = s.accessor.ReadAt(b, 0x10); err != nil {
		panic(err)
	}

	if b[0] != 0xfd {
		panic(&falloc.ECorrupted{store.Name(), 0x10})
	}

	s.RootMap.handle.Get(b[1:])
	return
}

// Open opens a Store in/from 'store'. If successful, methods on the returned Store
// can be used for data exchange. If rootMap then a Map from the handle pointed to by falloc.File root is loaded
// and set to store.RootMap.
// Open returns the store and an os.Error, if any.
func Open(store storage.Accessor, rootMap bool) (s *Store, err os.Error) {
	s = &Store{}

	defer func() {
		if e := recover(); e != nil {
			s = nil
			err = e.(os.Error)
		}
	}()

	if s.Store, err = hdb.Open(store); err != nil {
		panic(err)
	}

	s.accessor = s.Store.File().Accessor()

	if !rootMap {
		return
	}

	b := make([]byte, 8)
	if _, err = s.accessor.ReadAt(b, 0x10); err != nil {
		panic(err)
	}

	if b[0] != 0xfd {
		panic(&falloc.ECorrupted{store.Name(), 0x10})
	}

	var handle falloc.Handle
	handle.Get(b[1:])
	if s.RootMap, err = s.NewMapFromHandle(handle); err != nil {
		panic(err)
	}

	return
}

// NewMap creates a new empty Map in s, returns the Map and an os.Error if any.
func (s *Store) NewMap() (m *Map, err os.Error) {
	m = &Map{accessor: s.accessor, store: s}

	defer func() {
		if e := recover(); e != nil {
			m = nil
			err = e.(os.Error)
		}
	}()

	if m.handle, err = s.New(make([]byte, 8192*7)); err != nil {
		panic(err)
	}

	return
}

// NewMapFromHandle returns a newly created Map constructed from data found at an existing handle.
// The object referenced by handle must be a valid map
// (i.e. the object must have the format Map expects and can handle).
// Returned is the Map or an os.Error if any.
func (s *Store) NewMapFromHandle(handle falloc.Handle) (m *Map, err os.Error) {
	m = &Map{accessor: s.accessor, handle: handle, store: s}

	defer func() {
		if e := recover(); e != nil {
			m = nil
			err = e.(os.Error)
		}
	}()

	var b []byte
	if b, err = s.Get(handle); err != nil {
		panic(err)
	}

	if len(b) != 8192*7 {
		panic(&falloc.ECorrupted{s.accessor.Name(), 0x10})
	}

	fp := 0
	for i := range m.root {
		m.root[i].Get(b[fp:])
		fp += 7
	}
	return
}
