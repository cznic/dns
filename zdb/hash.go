// Copyright (c) 2010 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

// FNV-1a 27bit

package zdb

const (
	offset32a = 2166136261
	prime32a  = 16777619
)

type sum32 uint32

func newFNV1a() sum32 {
	return offset32a
}

func (s *sum32) write(b []byte) {
	h := *s
	for _, v := range b {
		h = (h ^ sum32(v)) * prime32a
	}
	*s = h
}

func (s *sum32) writeByte(b byte) {
	*s = (*s ^ sum32(b)) * prime32a
}

func (s *sum32) writeUint16(b uint16) {
	h := *s
	h = (h ^ sum32(b>>8)) * prime32a
	h = (h ^ sum32(b&255)) * prime32a
	*s = h
}

func (s *sum32) writeStr(b string) {
	h := *s
	for _, v := range b {
		h = (h ^ sum32(v)) * prime32a
	}
	*s = h
}

func (s sum32) hash(bits int) uint32 {
	if bits < 32 {
		return uint32((1<<uint(bits) - 1) & (s ^ s>>uint(bits)))
	}

	return uint32(s)
}
