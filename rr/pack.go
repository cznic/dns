// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz


package rr

import (
	"github.com/cznic/dns"
	"fmt"
)

// Bytes is a packed binary representation of RRs.
type Bytes []byte

// Append appends RRs to b. Append is a quite costly operation,
// so whenever possible collect related RRs firstly and then use Pack
// instead of e.g. Appending them one by one.
func (b *Bytes) Append(rrs RRs) {
	if len(rrs) != 0 {
		if len(*b) != 0 {
			b.Pack(append(b.Unpack(), rrs...))
		} else {
			b.Pack(rrs)
		}
	}
}

// Pack packs RRs to b.
func (b *Bytes) Pack(rrs RRs) {
	w := dns.NewWirebuf()
	for _, rec := range rrs {
		rec.Encode(w)
	}
	*b = make([]byte, len(w.Buf)) // repack tight
	copy(*b, w.Buf)
}

// Unpack unpacks b to RRs.
func (b Bytes) Unpack() (y RRs) {
	pos := 0
	for pos < len(b) {
		rec := &RR{}
		if err := rec.Decode(b, &pos, nil); err != nil {
			panic(fmt.Errorf("dns.Unpack\n% x\n at %04x %q", b, pos, err))
		}

		y = append(y, rec)
	}
	return
}

// Filter unpacks b to RRs. Only rrs for which 'want' returns true
// are included. For 'want' == nil, Filter == Unpack.
func (b Bytes) Filter(want func(r *RR) bool) (wanted, other RRs) {
	return b.Unpack().Filter(want)
}
