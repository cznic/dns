// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

package pcat

import (
	"github.com/cznic/dns/zdb"
	"sync"
)

// DB represents a pcat data store. It is intended for temporary DBs of e.g.
// some analytical tools. It has a rather big size overhead (~16M).
type DB struct {
	*zdb.Store
	rwm sync.RWMutex
}

// NewDB creates the DB in named file fn, truncating it if it already exists.
// If successful, methods on the returned DB can be used for I/O. It returns
// the DB and an error, if any.
func NewDB(fn string) (db *DB, err error) {
	var s *zdb.Store
	if s, err = zdb.New(fn, 22, 4); err != nil {
		return
	}

	return &DB{Store: s}, nil
}

// OpenDB opens a DB in/from named file fn. If successful, methods on the
// returned DB can be used for data exchange. OpenDB returns the DB and an
// error, if any.
func OpenDB(fn string) (db *DB, err error) {
	var s *zdb.Store
	if s, err = zdb.Open(fn); err != nil {
		return
	}

	return &DB{Store: s}, nil
}

// Close closes the DB. Further access to the DB has undefined behavior and may
// panic. It returns an error, if any.
func (db *DB) Close() error {
	return db.Store.Close()
}

// RGet reads the Record associated with partition and Id. It returns the
// data, key exists in ok and an error, if any. Get may return a non nil err
// iff !ok.
func (db *DB) RGet(partition uint32, Id int) (r Record, ok bool, err error) {
	var key [4]byte
	r.Id = Id
	p := 0
	put4(key[:], &p, Id)
	var value []byte
	db.rwm.RLock()         // R+
	defer db.rwm.RUnlock() // R-
	if value, ok, err = db.Get(partition, key[:]); err != nil || !ok {
		return
	}

	p = 0
	n := get2(value, &p)
	r.Query = append([]byte{}, value[p:p+n]...)
	p += n
	r.Reply = append([]byte{}, value[p:p+get2(value, &p)]...)
	return
}

// RSet stores r under partition and returns an error if any.
func (db *DB) RSet(partition uint32, r *Record) (err error) {
	var key [4]byte
	p := 0
	put4(key[:], &p, r.Id)
	value := make([]byte, 4+len(r.Query)+len(r.Reply))
	p = 0
	put2(value, &p, len(r.Query))
	copy(value[p:], r.Query)
	p += len(r.Query)
	put2(value, &p, len(r.Reply))
	copy(value[p:], r.Reply)
	db.rwm.Lock()         // W+
	defer db.rwm.Unlock() // W-
	return db.Set(partition, key[:], value)
}

func put(b []byte, p *int, i int) {
	b[*p] = byte(i)
	*p++
}

func put2(b []byte, p *int, i int) {
	put(b, p, i>>8)
	put(b, p, i)
}

func put4(b []byte, p *int, i int) {
	put2(b, p, i>>16)
	put2(b, p, i)
}

func get(b []byte, p *int) (i int) {
	i = int(b[*p])
	*p++
	return
}

func get2(b []byte, p *int) int {
	return get(b, p)<<8 | get(b, p)
}
