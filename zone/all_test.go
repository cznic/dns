// Copyright (c) 2010 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

package zone

import (
	"github.com/cznic/dns/rr"
	"errors"
	"flag"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"
)

var (
	optZone = flag.String("zone", "", "text zone file for the parser benchmark")
	optKeep = flag.Bool("keep", false, "keep generated test files")
)

func TestLoad(t *testing.T) {
	var a, b string
	var err, err2 error
	if err = Load(
		"./testzone",
		nil,
		func(r *rr.RR) bool {
			if r.TTL < 0 {
				r.TTL = 12345
			}
			if !strings.HasPrefix(r.Name, "n"+rr.Types[r.Type]+".") {
				err2 = errors.New("fail")
				t.Error("!!!", r)
				return false
			}

			a += r.String() + "\n"
			t.Log(r)
			return true
		},
	); err != nil {
		t.Fatal(err)
	}

	if err2 != nil {
		t.Fatal(err2)
	}

	f, err := ioutil.TempFile("", "gotest")
	if err != nil {
		t.Fatal(err)
	}

	fn := f.Name()
	err = ioutil.WriteFile(fn, []byte(a), 0600)
	ec := f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if ec != nil {
		t.Fatal(ec)
	}

	if err = Load(
		fn,
		nil,
		func(r *rr.RR) bool {
			if !strings.HasPrefix(r.Name, "n"+rr.Types[r.Type]+".") {
				err2 = errors.New("fail")
				t.Error("!!!", r)
				return false
			}

			b += r.String() + "\n"
			t.Log(r)
			return true
		},
	); err != nil {
		if !*optKeep {
			os.Remove(fn)
		}
		t.Fatal(err)
	}

	if err2 != nil {
		t.Fatal(err2)
	}

	if !*optKeep {
		os.Remove(fn)
	}
	if a != b {
		t.Fatalf("\n%s\n%s", a, b)
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
