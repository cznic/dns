// Copyright (c) 2010 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

// WIP: Package zdb provides a specialized DB engine for DNS zone(s)/a DNS
// server, i.e. some design parameters/decisions were made with the expected
// usage in mind wrt the forementioned usage patterns/clients.  E.g. a single
// map key hash could be for example only 27 bits (=> max 128M buckets), as the
// expected maximum number of distinct domain names in a single zone is
// estimated to be bellow 100M domains (and in an order of magnitudes less on
// average).
//
// This combined with a theoretically sound hash algorithm (FNV-1a) leads to an
// estimatedly acceptable, low enough collision rate, even with such short hash
// keys.
//
// In the noncolliding case, fetching an item's DB "pointer" requires reading
// just a few (typically 4 or 5) bytes from the DB store from an offset
// computed directly from the key hash.
//
// This is guessed to be fast enough to make the DNS server still perform
// within tolerable latency times on nowadays server grade HW (and it will get
// only better with the raise of SSD and simillar/better future "HD like"
// technologies).
//
// Note that the mentioned latency has (mostly) loose connection with the total
// server's QPS throughput, it makes slower the access per one CPU core only.
// And the number of cores in modern CPUs are currently surging, one can expect
// a server grade machine to have multicore processors.
//
package zdb

import (
	"bytes"
	"github.com/cznic/fileutil/hdb"
	"github.com/cznic/fileutil/storage"
	"fmt"
	"os"
	"path"
	"runtime"
	"strconv"
)

type hdbAccessor struct {
	delta    int64
	accessor storage.Accessor
}

func (a *hdbAccessor) Close() error {
	e1 := a.accessor.Sync()
	e2 := a.accessor.Close()
	if e1 != nil {
		return e1
	}

	return e2
}

// Implementation of storage.Accessor
func (a *hdbAccessor) Name() string {
	return a.accessor.Name()
}

// Implementation of storage.Accessor
func (a *hdbAccessor) ReadAt(b []byte, off int64) (n int, err error) {
	return a.accessor.ReadAt(b, off+a.delta)
}

// Implementation of storage.Accessor
func (a *hdbAccessor) Stat() (fi os.FileInfo, err error) {
	if fi, err = a.accessor.Stat(); err != nil {
		return
	}
	i := storage.NewFileInfo(fi)
	i.FSize -= a.delta
	return i, nil
}

// Implementation of storage.Accessor
func (a *hdbAccessor) Sync() (err error) {
	return a.accessor.Sync()
}

// Implementation of storage.Accessor
func (a *hdbAccessor) Truncate(size int64) error {
	return a.accessor.Truncate(size + a.delta)
}

// Implementation of storage.Accessor
func (a *hdbAccessor) WriteAt(b []byte, off int64) (n int, err error) {
	return a.accessor.WriteAt(b, off+a.delta)
}

// Implementation of storage.Accessor
func (a *hdbAccessor) BeginUpdate() error {
	return a.accessor.BeginUpdate()
}

// Implementation of storage.Accessor
func (a *hdbAccessor) EndUpdate() error {
	return a.accessor.EndUpdate()
}

func min(a, b int) int {
	if a < b {
		return a
	}

	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}

	return b
}

type header struct {
	magic     []byte
	hashWidth byte
	ptrBytes  byte
	reserved  []byte
}

func (h *header) rd(b []byte) error {
	if len(b) != 16 {
		return fmt.Errorf(
			"%s: expected 16 bytes, got %d bytes", me(), len(b),
		)
	}

	if h.magic = b[:6]; bytes.Compare(h.magic, []byte("ZONEDB")) != 0 {
		return fmt.Errorf(
			"%s: expected magic \"ZONEDB\", got %q", me, h.magic,
		)
	}

	if h.hashWidth = b[6]; h.hashWidth < 8 || h.hashWidth > 30 {
		return fmt.Errorf(
			"%s: expected hashWidth in 8...30, got %d", me, h.hashWidth,
		)
	}

	if h.ptrBytes = b[7]; h.ptrBytes < 4 || h.ptrBytes > 7 {
		return fmt.Errorf(
			"%s: expected ptrBytes in 4...7, got %d", me, h.ptrBytes,
		)
	}

	if h.reserved = b[8:]; bytes.Compare(h.reserved, []byte{0, 0, 0, 0, 0, 0, 0, 0}) != 0 {
		return fmt.Errorf(
			"%s: expected reserved all zeros, got \"% x\"", me, h.reserved,
		)
	}

	return nil
}

// Store is a DNS zone(s)/DNS server underlying DB engine.
//
// Any object ([]byte) can be used as the (hdb) DB root.
//
// The zdb model extends the hdb model with a hashmap of []byte keys to []byte
// values, (sub)partitioned with a table/zone/partition numeric IDs (uint32).
// The hashmap has a huge (hundreds of MB) fixed index prepended to the "real"
// hdb data. This overhead is a tradeoff between disk space and hashmap access
// speed, cf.  the specialization of this package as described in the package
// comment.
//
// Layout:
//  +--------+
//  | Header | Fixed size (16 bytes)
//  +--------+
//  | Index  | Variable size: 2^HashWidth * PtrBytes
//  +--------+
//  | hdb    | See the cznic/fileutil/hdb package
//  +--------+
//
// Header (@ 0x0000, 16):
//  +0x00, 6: Magic "ZONEDB"
//  +0x06, 1: HashWidth
//  +0x07, 1: PtrBytes
//  +0x08, 8: int64(0) // reserved
//
// Index (@ 0x0010, 2^HashWidth * PtrBytes):
//  +0*PtrBytes, PtrBytes: hdb handle for hash == 0
//  +1*PtrBytes, PtrBytes: hdb handle for hash == 1
//  +2*PtrBytes, PtrBytes: hdb handle for hash == 2
//  ...
//
// HDB (@ 0x0010 + 2^HashWidth * PtrBytes, variable size):
//  See the cznic/fileutil/falloc and cznic/fileutil/hdb packages documentations.
//
// The underlying hdb.Store is accessible as the Store field of Store.
// Additionaly the hdb.Store methods are emebeded into the Store method set.
//
// Note: The minimum allowed HashWidth == 8 bits is for testing only. The
// recomended value is N bits, such that 2^N > expected maximum number of keys
// in the DB.
type Store struct {
	*hdb.Store
	HashWidth int // R/O: FVN1a 32 bit hashes are tightened to HashWidth bits (8...30)
	PtrBytes  int // R/O: hdb "pointers" size, 4...7
	accessor  storage.Accessor
}

// Close closes the store. Further access to the store has undefined behavior
// and may panic. It returns an error, if any.
func (s *Store) Close() error {
	return s.Store.Close()
}

func (s *Store) hdelta(hash uint32) int64 {
	return 16 + int64(hash)*int64(s.PtrBytes)
}

func (s *Store) delta() int64 {
	return 16 + int64(1<<uint(s.HashWidth))*int64(s.PtrBytes)
}

// New creates the Store in named file fn, truncating it if it already exists.
// The hashWidth and ptrBytes arguments: see the Store type docs.  If
// successful, methods on the returned Store can be used for I/O. It returns
// the Store and an error, if any.
func New(fn string, hashWidth, ptrBytes int) (s *Store, err error) {
	s = &Store{
		HashWidth: min(max(hashWidth, 8), 29),
		PtrBytes:  min(max(ptrBytes, 4), 7),
	}

	defer func() {
		if e := recover(); e != nil {
			s = nil
			err = e.(error)
		}
	}()

	if s.accessor, err = storage.NewFile(fn, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0666); err != nil {
		return nil, fmt.Errorf("%s: %s", me(), err)
	}

	b := []byte{
		'Z', 'O', 'N', 'E', 'D', 'B',
		byte(s.HashWidth),
		byte(s.PtrBytes),
		0, 0, 0, 0, 0, 0, 0, 0,
	}
	if n, err := s.accessor.WriteAt(b, 0); n != len(b) || err != nil {
		return nil, fmt.Errorf("%s: %s", me(), err)
	}

	if s.Store, err = hdb.New(&hdbAccessor{s.delta(), s.accessor}); err != nil {
		return nil, fmt.Errorf("%s: %s", me(), err)
	}

	return
}

// Open opens a Store in/from named file fn. If successful, methods on the
// returned Store can be used for data exchange.  The HashWidth and PtrBytes
// are read from the DB.  Open returns the Store and an error, if any.
func Open(fn string) (s *Store, err error) {
	s = &Store{}

	defer func() {
		if e := recover(); e != nil {
			s = nil
			err = e.(error)
		}
	}()

	if s.accessor, err = storage.OpenFile(fn, os.O_RDWR, 0666); err != nil {
		return nil, fmt.Errorf("%s: %s", me(), err)
	}

	b := make([]byte, 16)
	if n, err := s.accessor.ReadAt(b, 0); n != 16 || err != nil {
		return nil, fmt.Errorf("%s: %d, %s", me(), n, err)
	}

	var h header
	if err = h.rd(b); err != nil {
		return nil, fmt.Errorf("%s: %s", me(), err)
	}

	s.HashWidth, s.PtrBytes = int(h.hashWidth), int(h.ptrBytes)
	if s.Store, err = hdb.Open(&hdbAccessor{s.delta(), s.accessor}); err != nil {
		return nil, fmt.Errorf("%s: %s", me(), err)
	}

	return
}

// me reports its calling site as a string.
func me() string {
	_, file, line, ok := runtime.Caller(1)
	if !ok {
		return "???"
	}

	return path.Base(file) + ":" + strconv.Itoa(line)
}
