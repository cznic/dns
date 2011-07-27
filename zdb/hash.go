// Copyright (c) 2010 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz


package zdb

const (
	h26 = 1<<26 - 1
	h13 = 1<<13 - 1
)

// FNV-1a 26bit
// http://www.isthe.com/chongo/tech/comp/fnv/index.html
func hash(b []byte) (h uint) {
	h = 2166136261
	for _, v := range b {
		h = (h ^ uint(v)) * 16777619
	}
	h = h>>26 ^ h&h26
	return
}
