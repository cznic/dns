// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz


package dns

import (
	"container/vector"
	"github.com/cznic/mathutil"
	"net"
	"strings"
	"testing"
)

func TestLabels(t *testing.T) {
	type data struct {
		str    string
		expect []string
	}

	test := [...]data{
		{"", []string{""}},
		{".", []string{""}},
		{"a.", []string{"a", ""}},
		{"a.b", []string{"a", "b"}},
		{".a", []string{"", "a"}},
		{"a.b.", []string{"a", "b", ""}},
		{"a.b.c", []string{"a", "b", "c"}},
		{"a.b.c.", []string{"a", "b", "c", ""}},
		{".a.b", []string{"", "a", "b"}},
		{".a.b.c", []string{"", "a", "b", "c"}},
		{".a.b.c.", []string{"", "a", "b", "c", ""}},
	}

	if _, err := Labels("www." + strings.Repeat("a", 63) + ".org"); err != nil {
		t.Fatal(10, err)
	}

	if _, err := Labels("www." + strings.Repeat("a", 64) + ".org"); err == nil {
		t.Fatal(20)
	}

	if _, err := Labels(strings.Repeat("123456789.", 25) + "12345"); err != nil {
		t.Fatal(30, err)
	}

	if _, err := Labels(strings.Repeat("123456789.", 25) + "123456"); err == nil {
		t.Fatal(40)
	}

	for i, pair := range test {
		got, err := Labels(pair.str)
		if err != nil {
			t.Fatal(50, err)
		}

		expect := pair.expect
		if len(got) != len(expect) {
			t.Fatalf("60 %d %q %d %d %v %v", i, pair.str, len(got), len(expect), got, expect)
		}

		for i, label := range got {
			if label != expect[i] {
				t.Fatalf("70 %d %q %q", i, label, expect[i])
			}
		}
	}
}

func TestMatchCount(t *testing.T) {
	type data struct {
		a, b string
		c    int
	}
	test := [...]data{
		{"", "", 1},
		{".", "", 1},
		{"", ".", 1},
		{".", ".", 1},

		{"a", "", 0},
		{"", "a", 0},
		{"a", "a", 1},
		{"a", "A", 1},
		{"A", "a", 1},
		{"A", "A", 1},

		{"a", ".", 0},
		{".", "a", 0},

		{"a.", "", 1},
		{"A.", "", 1},
		{"", "a.", 1},
		{"", "A.", 1},
		{"a.", "a.", 2},
		{"A.", "a.", 2},
		{"a.", "A.", 2},
		{"A.", "A.", 2},

		{"a", "a.", 0},
		{"a.", "a", 0},

		{".a", "", 0},
		{"", ".a", 0},
		{".a", ".a", 2},
		{".A", ".a", 2},
		{".a", ".A", 2},
		{".A", ".A", 2},

		{"a.b.c", "c", 1},
		{"a.b.c", "b.c", 2},
		{"a.b.c", "a.b.c", 3},

		{"c", "a.b.c", 1},
		{"b.c", "a.b.c", 2},
		{"a.b.c", "a.b.c", 3},
	}

	for i, x := range test {
		n, err := MatchCount(x.a, x.b)
		if err != nil {
			t.Fatal(err)
		}
		la, _ := Labels(x.a)
		lb, _ := Labels(x.b)
		if n != x.c {
			t.Fatalf("case %d: %q %q got %d want %d (%#v %#v)", i, x.a, x.b, n, x.c, la, lb)
		}
	}
}

func TestTreePut(t *testing.T) {
	data := [...]string{
		"cz.",
		"0.cz.",
		".",
		"org.",
		"com.",
		"wikipedia.org.",
		"mozilla.com.",
		"www.wikipedia.org.",
		"ftp.wikipedia.org.",
		"www.mozilla.com.",
		"ftp.mozilla.com.",
		"admin.www.wikipedia.org.",
		"admin.ftp.wikipedia.org.",
		"admin.www.mozilla.com.",
		"admin.ftp.mozilla.com.",
		"a.b.c.d.",
		"c.d.",
		"e.f.",
		"g.h.e.f.",
		"e.f.",
		"h.e.f.",
		"h.e.f.",
		".",
		"d.",
		"b.c.d.",
	}

	for ofs := range data {
		tr := NewTree()
		for i := range data {
			owner := data[(ofs+i)%len(data)]
			tr.Put(owner, owner)
			for j := 0; j <= i; j++ {
				owner := data[(ofs+j)%len(data)]
				x := tr.Get(owner)
				if s, ok := x.(string); !ok {
					t.Fatalf("owner %q: got '%T', expected 'string'", owner, x)
				} else {
					if s != owner {
						t.Fatalf("got %q, expected %q", s, owner)
					}
				}
			}
		}
	}
}

func TestTreePut2(t *testing.T) {
	data := &vector.StringVector{
		".",
		"1.",
		"1.0.",
		"1.1.",
		"1.0.0.",
		"1.0.1.",
		"1.1.0.",
		//"1.1.1.",
	}

	n := 1
	for mathutil.PermutationFirst(data); ; n++ {
		m := map[string]bool{}
		tr := NewTree()
		for _, owner := range *data {
			tr.Put(owner, owner)
			m[owner] = true
			for k := range m {
				x := tr.Get(k)
				if s, ok := x.(string); !ok {
					t.Fatalf("owner %q: got '%T', expected 'string'", owner, x)
				} else {
					if s != k {
						t.Fatalf("got %q, expected %q", s, k)
					}
				}
			}
		}

		if !mathutil.PermutationNext(data) {
			break
		}

	}
}

func TestTreeAdd(t *testing.T) {
	data := &vector.StringVector{
		".",
		"1.",
		"1.0.",
		"1.1.",
		"1.0.0.",
		"1.0.1.",
		"1.1.0.",
		//"1.1.1.",
	}

	n := 1
	for mathutil.PermutationFirst(data); ; n++ {
		m := map[string]bool{}
		tr := NewTree()
		for _, owner := range *data {
			tr.Add(owner, owner, func(interface{}) interface{} {
				t.Fatal(10)
				panic("unreachable")
			})
			m[owner] = true
			for k := range m {
				x := tr.Get(k)
				if s, ok := x.(string); !ok {
					t.Fatalf("owner %q: got '%T', expected 'string'", owner, x)
				} else {
					if s != k {
						t.Fatalf("got %q, expected %q", s, k)
					}
				}
			}
		}
		for _, owner := range *data {
			tr.Add(owner, owner, func(data interface{}) interface{} {
				return "!" + data.(string)
			})
		}
		for k := range m {
			x := tr.Get(k)
			if s, ok := x.(string); !ok {
				t.Fatalf("owner %q: got '%T', expected 'string'", k, x)
			} else {
				if s != "!"+k {
					t.Fatalf("got %q, expected !%q", s, k)
				}
			}
		}

		if !mathutil.PermutationNext(data) {
			break
		}

	}
}

func TestRevLookupName(t *testing.T) {
	const e4 = "155.39.97.145.in-addr.arpa."
	const e6 = "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."

	if s := strings.ToLower(RevLookupName(net.ParseIP("145.97.39.155"))); s != e4 {
		t.Fatal(10, s, "!=", e4)
	}

	if s := strings.ToLower(RevLookupName(net.ParseIP("2001:db8::567:89ab"))); s != e6 {
		t.Fatal(20, s, "!=", e6)
	}
}
