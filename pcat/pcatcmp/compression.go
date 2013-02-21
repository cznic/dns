// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

package main

import (
	"encoding/hex"
	"github.com/cznic/dns"
	"github.com/cznic/dns/msg"
	"log"
	"unsafe"
)

func idx(b []byte, p *byte) int {
	base := uintptr(unsafe.Pointer(&b[0]))
	ip := uintptr(unsafe.Pointer(p))
	return int(ip - base)
}

func (j *job) compression(id int, rtag string, src []byte) {
	cmp := dns.NewWirebuf()
	flag := false

	sniffer := func(p0, p9 *byte, tag dns.WireDecodeSniffed, info interface{}) {
		if flag {
			return
		}

		dn, ok := info.(dns.DomainName)
		if !ok {
			return
		}

		// "seek" according to p0
		srcX0 := idx(src, p0)
		cmp.Buf = append(cmp.Buf, make([]byte, srcX0-len(cmp.Buf))...)
		dn.Encode(cmp)
		srcX9 := idx(src, p9)
		cmpX9 := len(cmp.Buf) - 1
		dumpx := srcX0 //&^ 0xF
		if g, e := srcX9, cmpX9; g > e {
			j.err(
				id,
				1,
				SOC_ZIP,
				"%s\ndn: %q, ofs %d(%#x)\nexp:\n%sgot:\n%s",
				rtag, dn, srcX0, srcX0,
				hex.Dump(cmp.Buf[dumpx:cmpX9+1]),
				hex.Dump(src[dumpx:srcX9+1]),
			)
			flag = true
		}

	}

	m := &msg.Message{}
	p := 0
	if err := m.Decode(src, &p, sniffer); err != nil {
		log.Fatal("internal error", err)
	}
}
