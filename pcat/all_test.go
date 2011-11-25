// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

package pcat

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
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
