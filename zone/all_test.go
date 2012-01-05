// Copyright (c) 2010 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

package zone

import (
	"github.com/cznic/dns/rr"
	"flag"
	"os"
	"testing"
	"time"
)

var optZone = flag.String("zone", "", "text zone file for the parser benchmark")

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

func BenchmarkParser(b *testing.B) {
	b.StopTimer()
	fn := *optZone
	if fn == "" {
		b.Fatal("use -zone to specify the source file")
	}

	fi, err := os.Stat(fn)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(fi.Size())
	n := 0
	t0 := time.Now()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		if err := Load(
			fn,
			func(e string) bool {
				b.Fatal(e)
				panic("unreachable")
			},
			func(*rr.RR) bool {
				n++
				return true
			},
		); err != nil {
			b.Fatal(err)
		}
	}
	t1 := time.Now()
	b.StopTimer()
	d := t1.Sub(t0)
	T := d.Seconds()
	b.Logf("Parsed %d RRs in %v, %.0f RRs/sec", n, d, float64(n)/T)
}
