// Copyright (c) 2010 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz


package zone

import (
	"github.com/cznic/dns/rr"
	"testing"
)

func TestLoad(t *testing.T) {
	if err := Load(
		"./testzone",
		nil,
		func(r *rr.RR) bool {
			t.Log(r)
			return true
		},
	); err != nil {
		t.Fatal(err)
	}
}

func TestCompiler(t *testing.T) {
	t.Log("TODO") //TODO
}

func TestLoadBinary(t *testing.T) {
	t.Log("TODO") //TODO
}
