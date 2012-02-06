// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

package cache

import (
	"flag"
	"fmt"
	"github.com/cznic/dns/rr"
	"net"
	"runtime"
	"testing"
	"time"
)

var optPerc = flag.Int("perc", 0, "% of domains with one expired RR in BenchmarkCacheGetExpired")

func init() {
	flag.Parse()
}

func TestSecs0(t *testing.T) {
	if delta := Secs0() - time.Now().Unix(); delta < 0 || delta > 1 {
		t.Fatal(delta)
	}
}

func TestGet0(t *testing.T) {
	c := New()
	if found, hit := c.Get("."); hit {
		t.Fatal(10, found)
	}
}

func TestEnum0(t *testing.T) {
	c := New()
	var hit bool
	var x rr.Bytes
	c.Enum(".", func(path []string, found rr.Bytes) bool {
		x = found
		hit = true
		return false
	})
	if hit {
		t.Fatal(x.Unpack())
	}
}

func a(name string, ttl, addr int) *rr.RR {
	return &rr.RR{
		name,
		rr.TYPE_A,
		rr.CLASS_IN,
		int32(ttl),
		&rr.A{net.ParseIP(fmt.Sprintf("%d.%d.%d.%d", addr, addr, addr, addr))},
	}
}

func aaaa(name string, ttl, addr int) *rr.RR {
	return &rr.RR{
		".",
		rr.TYPE_AAAA,
		rr.CLASS_IN,
		int32(ttl),
		&rr.AAAA{net.ParseIP(fmt.Sprintf("::%d", addr))},
	}
}

func TestAddTTLM1(t *testing.T) {
	c := New()

	c.Add(rr.RRs{a(".", -1, 1)})
	if found, hit := c.Get("."); hit {
		t.Fatal(10, found)
	}
}

func TestAddTTL0(t *testing.T) {
	c := New()

	c.Add(rr.RRs{a(".", 0, 2)})
	if found, hit := c.Get("."); hit {
		t.Fatal(10, found)
	}
}

func TestAddTTL1(t *testing.T) {
	c := New()

	c.Add(rr.RRs{a(".", 1, 1)})
	if _, hit := c.Get("."); !hit {
		t.Fatal(10)
	}

	runtime.Gosched()
	if _, hit := c.Get("."); !hit {
		t.Fatal(20)
	}

	<-time.After(1.1e9)
	if found, hit := c.Get("."); hit {
		t.Fatal(30, found)
	}
}

func TestAddTTL1_2(t *testing.T) {
	c := New()

	c.Add(rr.RRs{a(".", 1, 1)})
	c.Add(rr.RRs{a(".", 2, 2)})
	if _, hit := c.Get("."); !hit {
		t.Fatal(10)
	}

	runtime.Gosched()
	if _, hit := c.Get("."); !hit {
		t.Fatal(20)
	}

	<-time.After(1.1e9)
	if found, hit := c.Get("."); hit {
		t.Fatal(30, found)
	}
}

func TestAddTTL1_2b(t *testing.T) {
	c := New()

	c.Add(rr.RRs{a(".", 1, 1)})
	c.Add(rr.RRs{aaaa(".", 3, 2)})
	if _, hit := c.Get("."); !hit {
		t.Fatal(10)
	}

	runtime.Gosched()
	if _, hit := c.Get("."); !hit {
		t.Fatal(20)
	}

	<-time.After(1.1e9)
	var found rr.RRs
	var hit bool
	if found, hit = c.Get("."); !hit {
		t.Fatal(30)
	}

	if n := len(found); n != 1 {
		t.Fatal(40, n, "!= 1")
	}

	if typ := found[0].Type; typ != rr.TYPE_AAAA {
		t.Fatal(50, typ, rr.TYPE_AAAA)
	}

	<-time.After(2e9)
	if found, hit := c.Get("."); hit {
		t.Fatal(60, found)
	}
}

func TestMerge(t *testing.T) {
	c := New()

	c.Add(rr.RRs{a(".", 10, 1)})
	c.Add(rr.RRs{a(".", 1, 1)}) // more recent add wins on equality (which disregards TTL)
	var found rr.RRs
	var hit bool
	if found, hit = c.Get("."); !hit {
		t.Fatal(10)
	}

	if n := len(found); n != 1 {
		t.Fatal(20, n, "!= 1")
	}

	if ttl := found[0].TTL; ttl != 1 {
		t.Fatal(30, ttl, "!= 1")
	}

	c.Add(rr.RRs{a(".", 10, 1)})
	if found, hit = c.Get("."); !hit {
		t.Fatal(40)
	}

	if n := len(found); n != 1 {
		t.Fatal(50, n, "!= 1")
	}

	if ttl := found[0].TTL; ttl != 10 {
		t.Fatal(60, ttl, "!= 10")
	}

}

func TestAddNames(t *testing.T) {
	c := New()

	c.Add(rr.RRs{a("x.", 10, 1), a("y.", 10, 1)})
	var found rr.RRs
	var hit bool
	if found, hit = c.Get("x."); !hit {
		t.Fatal(10)
	}

	if n := len(found); n != 1 {
		t.Fatal(20, n, "!= 1")
	}

	if name := found[0].Name; name != "x." {
		t.Fatal(30, name, `!= "x."`)
	}

	if found, hit = c.Get("y."); !hit {
		t.Fatal(40)
	}

	if n := len(found); n != 1 {
		t.Fatal(50, n, "!= 1")
	}

	if name := found[0].Name; name != "y." {
		t.Fatal(60, name, `!= "y."`)
	}

}

func BenchmarkCacheGet(b *testing.B) {
	b.StopTimer()
	c := New()
	domains := make([]string, b.N)
	rdA := &rr.A{}
	rrA := &rr.RR{"", rr.TYPE_A, rr.CLASS_IN, 24 * 3600, rdA}
	rrs := rr.RRs{rrA}
	for i := range domains {
		domain := fmt.Sprintf("i%d.example.com.", i)
		domains[i] = domain
		rdA.Address = net.ParseIP(fmt.Sprintf("%d.%d.%d.%d", byte(i>>24), byte(i>>16), byte(i>>8), byte(i)))
		rrA.Name = domain
		c.Add(rrs)
	}

	b.StartTimer()
	for _, domain := range domains {
		c.Get(domain)
	}
}

func BenchmarkCacheGetExpired(b *testing.B) {
	b.StopTimer()
	perc := *optPerc
	switch {
	case perc < 0:
		perc = 0
	case perc > 100:
		perc = 100
	}
	c := New()
	domains := make([]string, b.N)

	// The NS record will not expire.
	rdNS := &rr.NS{}
	rrNS := &rr.RR{"", rr.TYPE_NS, rr.CLASS_IN, 24 * 3600, rdNS}

	// The A record will be expired in perc %. That forces unpack/update/repack of the RR set.
	rdA := &rr.A{}
	rrA := &rr.RR{"", rr.TYPE_A, rr.CLASS_IN, 0, rdA}

	rrs := rr.RRs{rrA, rrNS}
	for i := range domains {
		domain := fmt.Sprintf("i%d.example.com.", i)
		domains[i] = domain
		rdA.Address = net.ParseIP(fmt.Sprintf("%d.%d.%d.%d", byte(i>>24), byte(i>>16), byte(i>>8), byte(i)))
		rdNS.NSDName = "ns." + domain
		rrA.Name = domain
		rrNS.Name = domain
		switch m := i % 100; {
		case m < perc:
			rrA.TTL = 1
		default:
			rrA.TTL = 24 * 3600
		}
		c.Add(rrs)
	}
	<-time.After(1.1e9)

	b.StartTimer()
	for _, domain := range domains {
		c.Get(domain)
	}
}
