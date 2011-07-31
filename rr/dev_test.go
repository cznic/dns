// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz


package rr

import (
	"testing"
)

func TestEDNS0(t *testing.T) {
	if !*optDev {
		return
	}

	const ttl = 0x01021001
	var ext EXT_RCODE
	ext.FromTTL(ttl)
	t.Log("EXT_RCODE:\n", &ext)

	rd := &OPT{}
	rd.Values = append(rd.Values, OPT_DATA{3, []byte{3, 4, 5}})
	rd.Values = append(rd.Values, OPT_DATA{5, []byte{5, 6, 7, 8}})
	r := &RR{"", TYPE_OPT, Class(4096), ttl, rd}
	t.Log("OPT:\n", r)
}
