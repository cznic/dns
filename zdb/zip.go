// Copyright (c) 2010 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz


package zdb

type zip uint64

//TODO 9byte zip
func (z zip) put(b *[]byte) {
	var buf [10]byte
	n := 9
	for {
		v := byte(z & 0x7f)
		if n != 9 {
			v |= 0x80
		}
		buf[n] = v
		n--
		if z = z >> 7; z == 0 {
			break
		}
	}
	*b = append(*b, buf[n+1:]...)
}

func (z zip) put2(b []byte) (nbytes int) {
	var buf [10]byte
	n := 9
	for {
		v := byte(z & 0x7f)
		if n != 9 {
			v |= 0x80
		}
		buf[n] = v
		n--
		if z = z >> 7; z == 0 {
			break
		}
	}
	copy(b, buf[n+1:])
	return 9 - n
}

func (z *zip) get(b []byte) (nbytes int) {
	x := zip(0)
	for _, v := range b {
		v7 := v & 0x7f
		x = x<<7 | zip(v7)
		nbytes++
		if v == v7 {
			*z = x
			return
		}
	}
	panic("unreachable")
}
