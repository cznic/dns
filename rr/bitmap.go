// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

package rr

import (
	"fmt"
	"sort"
	"strings"
)

// TypesEnccode encodes types into bitmap bits (RFC 4034/4.1.2).
func TypesEncode(types []Type) (bits []byte) {
	if len(types) == 0 {
		return
	}

	m := map[int]bool{}
	for _, typ := range types {
		m[int(typ)] = true
	}

	v := make([]int, len(m))
	i := 0
	for typ := range m {
		v[i] = typ
		i++
	}

	sort.Ints(v)
	first, next := 0, 0
	var blockbits [32]byte

	for first < len(v) {

		window := v[first] >> 8
		for next = first + 1; next < len(v); next++ {
			if v[next]>>8 != window {
				break
			}
		}

		block := v[first:next]
		for i := range blockbits[:] {
			blockbits[i] = 0
		}

		for _, typ := range block {
			blockbits[(typ&0xFF)>>3] |= (0x80 >> uint(typ&7))
		}

		last := 31
		for ; blockbits[last] == 0; last-- {
		}

		bits = append(bits, byte(window), byte(last+1))
		bits = append(bits, blockbits[:last+1]...)
		first = next
	}

	return
}

// TypesDecode decodes RR Type bitmap bits (RFC 4034/4.1.2).
func TypesDecode(bits []byte) (types []Type, err error) {
	p := 0
	for p < len(bits) {
		window := int(bits[p]) << 8
		p++
		length := int(bits[p])
		p++
		next := p + length
		if next > len(bits) {
			return nil, fmt.Errorf("bitmap decode - buffer underflow")
		}

		bitmap := bits[p:next]
		p = next
		for ibyte, octet := range bitmap {
			if octet != 0 {
				for ibit := 0; ibit < 8; ibit++ {
					if octet&0x80 != 0 {
						x := window | (ibyte << 3) | ibit
						types = append(types, Type(x))
					}
					octet <<= 1
				}
			}
		}
	}
	return
}

func TypesString(types []Type) string {
	a := []string{}
	for _, typ := range types {
		a = append(a, typ.String())
	}
	return strings.Join(a, " ")
}
