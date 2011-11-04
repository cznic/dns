// Copyright (c) 2010 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

package zdb

import (
	"bytes"
	"github.com/cznic/fileutil/falloc"
	"os"
)

/* 

Chunk layout:

PtrBytes: next pointer (collision chain)
       2: partition
       2: key length
       2: value length
    lenK: key
    lenV: value
*/

func (s *Store) getHandle(b []byte) (handle falloc.Handle) {
	for i := 0; i < s.PtrBytes; i++ {
		handle = handle<<8 | falloc.Handle(b[i])
	}
	return
}

func (s *Store) setHandle(handle falloc.Handle, off int64) (err os.Error) {
	b := make([]byte, s.PtrBytes)
	for i := len(b) - 1; i >= 0; i-- {
		b[i] = byte(handle)
		handle >>= 8
	}
	_, err = s.accessor.WriteAt(b, off)
	return
}

func (s *Store) putHandle(handle falloc.Handle, b []byte) {
	for i := s.PtrBytes - 1; i >= 0; i-- {
		b[i] = byte(handle)
		handle >>= 8
	}
}

func (s *Store) compose(next falloc.Handle, partition uint16, key, value []byte) (b []byte) {
	lenK, lenV := len(key), len(value)
	b = make([]byte, s.PtrBytes)
	s.putHandle(next, b)
	b = append(b,
		byte(partition>>8), byte(partition),
		byte(lenK>>8), byte(lenK),
		byte(lenV>>8), byte(lenV),
	)
	b = append(b, key...)
	b = append(b, value...)
	return
}

// Set stores value under partition, key in Store and returns an os.Error if any.
func (s *Store) Set(partition uint16, key, value []byte) (err os.Error) {
	lenK := len(key)
	var h = newFNV1a()
	h.writeUint16(partition)
	h.write(key)
	var ptrbuf = make([]byte, s.PtrBytes)
	hdelta := s.hdelta(h.hash(s.HashWidth))
	if _, err = s.accessor.ReadAt(ptrbuf, hdelta); err != nil {
		return
	}

	handle := s.getHandle(ptrbuf)
	if handle == 0 { // no collision, not set before
		if handle, err = s.Store.New(s.compose(0, partition, key, value)); err != nil {
			return
		}

		return s.setHandle(handle, hdelta)
	}

	// collision or overwrite existing
	var chunk []byte
	for {
		if chunk, err = s.Store.Get(handle); err != nil {
			return
		}

		if len(chunk) < s.PtrBytes+6 {
			return &falloc.ECorrupted{s.accessor.Name(), int64(handle) << 4}
		}

		rdoff := s.PtrBytes
		rdpartition := uint16(chunk[rdoff])<<8 | uint16(chunk[rdoff+1])
		rdoff += 2
		if rdpartition == partition {
			rdLenK := int(chunk[rdoff])<<8 | int(chunk[rdoff+1])
			rdoff += 4
			if rdLenK == lenK { // chunk key length OK
				if rdoff+lenK > len(chunk) {
					return &falloc.ECorrupted{s.accessor.Name(), int64(handle) << 4}
				}

				if bytes.Compare(key, chunk[rdoff:rdoff+lenK]) == 0 { // hit, overwrite
					rdoff += lenK
					next := s.getHandle(chunk)
					return s.Store.Set(handle, s.compose(next, partition, key, value))
				}
			}
		}

		next := s.getHandle(chunk)
		if next == 0 { // collision, not set before
			if next, err = s.Store.New(s.compose(0, partition, key, value)); err != nil {
				return
			}

			s.putHandle(next, chunk)          // link
			return s.Store.Set(handle, chunk) // write back updated chunk
		}

		handle = next
	}

	panic("unreachable")
}

// Get reads the value associated with partition, key in Store. It returns the
// data, key exists in ok and an os.Error, if any. Get may return a non nil err
// iff !ok.
func (s *Store) Get(partition uint16, key []byte) (value []byte, ok bool, err os.Error) {
	lenK := len(key)
	var h = newFNV1a()
	h.writeUint16(partition)
	h.write(key)
	var ptrbuf = make([]byte, s.PtrBytes)
	hdelta := s.hdelta(h.hash(s.HashWidth))
	if _, err = s.accessor.ReadAt(ptrbuf, hdelta); err != nil {
		return
	}

	handle := s.getHandle(ptrbuf)
	if handle == 0 { // not found
		return nil, false, nil
	}

	// chunk for this hash exists
	var chunk []byte
	for {
		if chunk, err = s.Store.Get(handle); err != nil {
			return
		}

		if len(chunk) < s.PtrBytes+6 {
			return nil, false, &falloc.ECorrupted{s.accessor.Name(), int64(handle) << 4}
		}

		rdoff := s.PtrBytes
		rdpartition := uint16(chunk[rdoff])<<8 | uint16(chunk[rdoff+1])
		rdoff += 2
		if rdpartition == partition { // chunk partition OK
			rdLenK := int(chunk[rdoff])<<8 | int(chunk[rdoff+1])
			rdoff += 2
			rdLenV := int(chunk[rdoff])<<8 | int(chunk[rdoff+1])
			rdoff += 2
			if rdLenK == lenK { // chunk key length OK
				if rdoff+lenK > len(chunk) {
					return nil, false, &falloc.ECorrupted{s.accessor.Name(), int64(handle) << 4}
				}

				if bytes.Compare(key, chunk[rdoff:rdoff+lenK]) == 0 { // hit
					rdoff += lenK
					if rdoff+rdLenV != len(chunk) {
						return nil, false, &falloc.ECorrupted{s.accessor.Name(), int64(handle) << 4}
					}

					// Success
					return chunk[rdoff : rdoff+rdLenV], true, nil
				}
			}
		}

		next := s.getHandle(chunk)
		if next == 0 { // not found 
			return nil, false, nil
		}

		handle = next
	}

	panic("unreachable")
}
