// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

package main

import (
	"bytes"
	"github.com/cznic/dns/pcat"
	"testing"
)

func mkrec(id, part int) (r pcat.Record) {
	r.Id = id
	r.Query = make([]byte, 16+id&0x1f)
	for i := range r.Query {
		r.Query[i] = byte(id + i + part)
	}
	r.Reply = make([]byte, 16+id&0x1f)
	for i := range r.Query {
		r.Reply[i] = byte(id - i - part)
	}
	return
}

func TestSetup(t *testing.T) {
	const nrecs = 2500
	var xa, xb []byte
	for i := 0; i < nrecs; i++ {
		ra, rb := mkrec(i^0x55, 1), mkrec(i^0xaa, 2)
		xa = append(xa, []byte(ra.String()+"\n")...)
		xb = append(xb, []byte(rb.String()+"\n")...)
	}
	j := &job{
		fa:  bytes.NewBuffer(xa),
		fb:  bytes.NewBuffer(xb),
		fna: "A",
		fnb: "B",
	}
	setup(j, func(j *job) {
		t.Log(j.db.File().Accessor().Name())
		// Check we can get back all of the records
		for i := 0; i < nrecs; i++ {
			ra, rb := mkrec(i^0x55, 1), mkrec(i^0xaa, 2)
			ga, ok, err := j.db.RGet(1, i^0x55)
			if err != nil {
				t.Fatal(err)
			}

			if !ok {
				t.Fatal(i, "record not found")
			}

			if g, e := ga.String(), ra.String(); g != e {
				t.Fatalf("%d\n%s\n%s\n", i, g, e)
			}

			gb, ok, err := j.db.RGet(2, i^0xaa)
			if err != nil {
				t.Fatal(err)
			}

			if !ok {
				t.Fatal(i, "record not found")
			}

			if g, e := gb.String(), rb.String(); g != e {
				t.Fatalf("%d\n%s\n%s\n", i, g, e)
			}
		}
		// Check next records don't exist
		_, ok, err := j.db.RGet(1, nrecs^0x55)
		if err != nil {
			t.Fatal(err)
		}

		if ok {
			t.Fatal(nrecs, "unexpected record found")
		}

		_, ok, err = j.db.RGet(2, nrecs^0xaa)
		if err != nil {
			t.Fatal(err)
		}

		if ok {
			t.Fatal(nrecs, "unexpected record found")
		}
	})
}
