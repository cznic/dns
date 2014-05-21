// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

package pcat

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"io/ioutil"
	"path/filepath"
)

type testCase struct {
	src string
	re  string // error RE to check
}

var testCases = []testCase{
	{"abc", `[Uu]nexp.*"a"`},
	{"1bc", `[Uu]nexp.*"b"`},
	{"12c", `[Uu]nexp.*"c"`},
	{"123", `[Uu]nexp.*"\\x00"`},
	{"4\n", `[Uu]nexp.*"\\x00"`},
	{"5\nx", `[Uu]nexp.*"x"`},
	{"6\nax", `[Uu]nexp.*"x"`},
	{"7\nabx", `[Uu]nexp.*"x"`},
	{"8\nabcx", `[Uu]nexp.*"x"`},
	{"9\nabcdx", `[Uu]nexp.*"x"`},
	{"10\n\n", `[Uu]nexp.*"\\n"`},
	{"11\na\n", `[Uu]nexp.*"\\n"`},
	{"12\nabc\n", `[Uu]nexp.*"\\n"`},
	{"13\nab", `[Uu]nexp.*"\\x00"`},
	{"14\nab\n", ``},
	{"15\nef\nx", `[Uu]nexp.*"x"`},
	{"16\nef\nax", `[Uu]nexp.*"x"`},
	{"17\nef\nabx", `[Uu]nexp.*"x"`},
	{"18\nef\nabcx", `[Uu]nexp.*"x"`},
	{"19\nef\nabcdx", `[Uu]nexp.*"x"`},
	{"20\nef\nab", ``},
	{"21\nef\nabcd", ``},
}

func TestScanner(t *testing.T) {
	for i, test := range testCases {
		re := test.re
		switch err := Scan(
			fmt.Sprintf("testCase-%d", i),
			strings.NewReader(test.src),
			func(*Record) bool { return true },
		); {
		case err == nil && re != "":
			t.Errorf("test case %d\nsrc:\n%s\nmissing error %s", i, test.src, re)
		case err != nil && re == "":
			t.Errorf("test case %d\nsrc:\n%s\nunexpected error %s", i, test.src, err)
		case err != nil && re != "":
			matched, err2 := regexp.MatchString(re, err.Error())
			if err2 != nil {
				t.Fatal("internal error", err2)
			}

			if !matched {
				t.Errorf(
					"\nsrc:\n%s\nerr: %s\nproblem: doesn't match %q",
					test.src, err, re,
				)
			}
		}
	}
}

func TestScannerB(t *testing.T) {
	const src = `

123
010123456789abcdef0123456789ABCDEF

456
020123456789abcdef0123456789abcdef
030123456789abcdef0123456789ABCDEF

`
	rnum := 0
	err := Scan(
		"TestScannerB",
		strings.NewReader(src),
		func(r *Record) bool {
			switch rnum++; rnum {
			default:
				t.Fatal("unexpected record serial", rnum)
			case 1:
				if g, e := r.String(), `123
010123456789abcdef0123456789abcdef
`; g != e {
					t.Errorf("record %d, expected:\n%s\ngot:\n%s", rnum, e, g)
				}
			case 2:
				if g, e := r.String(), `456
020123456789abcdef0123456789abcdef
030123456789abcdef0123456789abcdef`; g != e {
					t.Errorf("record %d, expected:\n%s\ngot:\n%s", rnum, e, g)
				}
			}
			return true
		},
	)
	if err != nil {
		t.Fatal(err)
	}
}

func mkrec(id, part int) (r Record) {
	r.Id = id
	r.Query = make([]byte, 16+id&0x1f)
	for i := range r.Query {
		r.Query[i] = byte(id + i + part)
	}
	r.Reply = make([]byte, 16+id&0x1f)
	for i := range r.Reply {
		r.Reply[i] = byte(id - i - part)
	}
	return
}

func TestDB(t *testing.T) {
	const (
		recs  = 400
		parts = 10
	)

	tempDir, err := ioutil.TempDir("", "test-pcat-")
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(tempDir)

	fn := filepath.Join(tempDir, "temp_db")
	db, err := NewDB(fn)
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		var err error
		if db != nil {
			err = db.Close()
		}
		if err != nil {
			t.Fatal(err)
		}
	}()

	t.Log("DB created")
	for recn := 0; recn < recs; recn++ {
		for part := 0; part < parts; part++ {
			r := mkrec(recn, part)
			if err := db.RSet(uint32(part), &r); err != nil {
				db.Close()
				t.Fatal(err)
			}
		}
	}
	t.Log("DB written")
	for recn := 0; recn < recs; recn++ {
		for part := 0; part < parts; part++ {
			g, ok, err := db.RGet(uint32(part), recn)
			if err != nil {
				db.Close()
				db = nil
				t.Fatal(err)
			}

			if !ok {
				db.Close()
				db = nil
				t.Fatal(recn, part, " record not found")
			}

			e := mkrec(recn, part)
			if gs, es := g.String(), e.String(); gs != es {
				db.Close()
				db = nil
				t.Errorf("rec: %d, part: %d\nexp:\n%s\ngot:\n%s", recn, part, gs, es)
			}

		}
	}
	t.Log("DB checked")

	err = db.Close()
	if err != nil {
		t.Fatal(err)
	}

	t.Log("DB closed")
	db, err = OpenDB(fn)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("DB opened")
	for recn := 0; recn < recs; recn++ {
		for part := 0; part < parts; part++ {
			g, ok, err := db.RGet(uint32(part), recn)
			if err != nil {
				db.Close()
				db = nil
				t.Fatal(err)
			}

			if !ok {
				db.Close()
				db = nil
				t.Fatal(recn, part, " record not found")
			}

			e := mkrec(recn, part)
			if gs, es := g.String(), e.String(); gs != es {
				db.Close()
				db = nil
				t.Errorf("rec: %d, part: %d\nexp:\n%s\ngot:\n%s", recn, part, gs, es)
			}

		}
	}
	t.Log("DB checked")
}
