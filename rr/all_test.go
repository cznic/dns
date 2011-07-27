// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz


package rr

import (
	"bytes"
	"net"
	"strconv"
	"strings"
	"testing"
)

type enctest struct {
	t []Type
	b []byte
}

var enctests = []enctest{
	{[]Type{}, []byte{}},
	{[]Type{TYPE_A}, []byte{0, 1, 0x40}},
	{[]Type{TYPE_A, TYPE_MX}, []byte{0, 2, 0x40, 0x01}},
	{[]Type{TYPE_A, TYPE_MX, TYPE_RRSIG}, []byte{0, 6, 0x40, 0x01, 0x00, 0x00, 0x00, 0x02}},
	{[]Type{TYPE_A, TYPE_MX, TYPE_RRSIG, TYPE_NSEC}, []byte{0, 6, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03}},
	{[]Type{TYPE_A, TYPE_MX, TYPE_RRSIG, TYPE_NSEC, Type(1234)}, []byte{
		0x00, 0x06, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03,
		0x04, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x20,
	}},
	{[]Type{TYPE_MX, TYPE_RRSIG, TYPE_NSEC, Type(1234)}, []byte{
		0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03,
		0x04, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x20,
	}},
	{[]Type{TYPE_RRSIG, TYPE_NSEC, Type(1234)}, []byte{
		0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
		0x04, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x20,
	}},
	{[]Type{TYPE_NSEC, Type(1234)}, []byte{
		0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x04, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x20,
	}},
	{[]Type{Type(1234)}, []byte{
		0x04, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x20,
	}},
}

func hd(t *testing.T, msg string, b []byte) {
	t.Logf("%s len==%d", msg, len(b))
	for y := 0; ; y += 16 {
		if y >= len(b) {
			return
		}
		s := b[y:]
		if len(s) > 16 {
			s = s[:16]
		}
		t.Logf("%04x: % x", y, s)
	}
}

func ts(typ Type) (s string) {
	defer func() {
		if e := recover(); e != nil {
			s = "TYPE" + strconv.Itoa(int(typ))
		}
	}()
	return typ.String()
}

func td(t *testing.T, msg string, types []Type) {
	t.Logf("%s len==%d", msg, len(types))
	a := []string{}
	for _, typ := range types {
		a = append(a, ts(typ))
	}
	t.Log(strings.Join(a, " "))
}

func TestTypesEncode(t *testing.T) {
	for _, test := range enctests {
		bits := TypesEncode(test.t)
		if !bytes.Equal(bits, test.b) {
			td(t, "encode", test.t)
			hd(t, "expected", test.b)
			hd(t, "got", bits)
			t.Fatal("!=")
		}

	}
}

func TestTypesDecode(t *testing.T) {
	for _, test := range enctests {
		got, err := TypesDecode(test.b)
		if err != nil {
			t.Fatal(err)
		}

		for i, typ := range test.t {
			if i >= len(got) || typ != got[i] {
				td(t, "expected", test.t)
				td(t, "got", got)
				t.Fatal("!=")
			}
		}
	}
}

func Test0(t *testing.T) {
	data := RRs{
		&RR{"nA.example.com", TYPE_A, CLASS_IN, 0,
			&A{net.ParseIP("1.2.3.4")}},
		&RR{"nAAAA.example.com", TYPE_AAAA, CLASS_IN, 1,
			&AAAA{net.ParseIP("::1")}},
		&RR{"nCNAME.example.com", TYPE_CNAME, CLASS_IN, 2,
			&CNAME{"cname.example.com"}},
		&RR{"nDNSKEY.example.com", TYPE_DNSKEY, CLASS_IN, 3,
			&DNSKEY{2, 3, 4,
				[]byte{11, 12, 13, 14, 15, 16, 17, 18, 19}}},
		&RR{"nDS.example.com", TYPE_DS, CLASS_IN, 4,
			&DS{0x1234, 0x56, HashAlgorithmSHA1,
				[]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}}},
		&RR{"nMX.example.com", TYPE_MX, CLASS_IN, 5,
			&MX{0x1234, "exchange.example.com."}},
		&RR{"nNS.example.com", TYPE_NS, CLASS_IN, 6,
			&NS{"ns.example.com"}},
		&RR{"nNSEC3.example.com", TYPE_NSEC3, CLASS_IN, 7,
			&NSEC3{
				NSEC3PARAM{0x01, 0x02, 0x0304, []byte{11, 12, 13, 14, 15, 16, 17, 18, 19}},
				[]byte{1, 3, 5, 7, 11},
				[]byte{0, 6, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03},
			}},
		&RR{"nNSEC3PARAM.example.com", TYPE_NSEC3PARAM, CLASS_IN, 8,
			&NSEC3PARAM{0x01, 0x02, 0x0304, []byte{11, 12, 13, 14, 15, 16, 17, 18, 19}}},
		&RR{"nPTR.example.com", TYPE_PTR, CLASS_IN, 9,
			&PTR{"ptr.example.com"}},
		&RR{"nRRSIG.example.com", TYPE_RRSIG, CLASS_IN, 10,
			&RRSIG{TYPE_A, AlgorithmDSA_SHA1, 2, 3, 0x87654321, 0x12345678, 0x1234, "signer.example.com.",
				[]byte{0, 6, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03}},
		},
		&RR{"nSOA.example.com", TYPE_SOA, CLASS_IN, 11,
			&SOA{"mname.example.com.", "rname.example.com.", 0x12345678, 0x123456, 0x98765, 0x1331, 0x9812}},
		&RR{"nTXT.example.com", TYPE_TXT, CLASS_IN, 12, &TXT{"the quick \" brown fox"}},
	}

	s := ""
	for _, r := range data {
		s += r.String() + "\n"
	}
	t.Logf(s)

	var bytes Bytes
	bytes.Pack(data)
	cmp := bytes.Unpack()

	s2 := ""
	for _, r := range data {
		s2 += r.String() + "\n"
	}
	if s2 != s {
		t.Logf(s2)
		t.Fatal(20)
	}

	for i, r := range cmp {
		if r.Name != "n"+r.Type.String()+".example.com." {
			t.Fatal(30, r.Name)
		}

		if int(r.TTL) != i {
			t.Fatal(40)
		}

		if r.Class != CLASS_IN {
			t.Fatal(50)
		}
	}

}

func TestEqual(t *testing.T) {
	a := &RR{"example.com", TYPE_A, CLASS_IN, 0, &A{net.ParseIP("1.2.3.4")}}
	if !a.Equal(a) { // a == a
		t.Fatal(10, "false != true")
	}

	b := &RR{"example.com", TYPE_A, CLASS_IN, 1, &A{net.ParseIP("1.2.3.4")}}
	if !b.Equal(b) { // b == b
		t.Fatal(20, "false != true")
	}

	if !a.Equal(b) { // a == b, TTL must be ignored
		t.Fatal(30, "false != true")
	}

	b = &RR{"EXAMPLE.COM", TYPE_A, CLASS_IN, 1, &A{net.ParseIP("1.2.3.4")}}
	if !a.Equal(b) { // a == b, name case must be ignored
		t.Fatal(40, "false != true")
	}

	b = &RR{"example.org", TYPE_A, CLASS_IN, 1, &A{net.ParseIP("1.2.3.4")}}
	if a.Equal(b) { // a != b, (name)
		t.Fatal(45, "true != false")
	}

	b = &RR{"example.com", TYPE_AAAA, CLASS_IN, 1, &AAAA{net.ParseIP("1.2.3.4")}}
	if a.Equal(b) { // a != b (type)
		t.Fatal(50, "true != false")
	}

	b = &RR{"example.com", TYPE_A, CLASS_CH, 1, &A{net.ParseIP("1.2.3.4")}}
	if a.Equal(b) { // a != b (class)
		t.Fatal(60, "true != false")
	}

	b = &RR{"example.com", TYPE_A, CLASS_IN, 1, &A{net.ParseIP("1.2.3.5")}}
	if a.Equal(b) { // a != b (ip)
		t.Fatal(60, "true != false")
	}

}

func TestSetAdd(t *testing.T) {
	set := RRs{}
	set.SetAdd(RRs{&RR{"example.com", TYPE_A, CLASS_IN, 0, &A{net.ParseIP("1.2.3.4")}}})
	if len(set) != 1 {
		t.Fatal(10, len(set), "!= 1")
	}

	if set[0].Name != "example.com" {
		t.Fatal(20, set[0].Name, "!= example.com")
	}

	set.SetAdd(RRs{&RR{"example.com", TYPE_A, CLASS_CH, 0, &A{net.ParseIP("1.2.3.4")}}})

	if len(set) != 2 { // dif class => 1 + 1
		t.Log(set)
		t.Fatal(30, len(set), "!= 2")
	}

	ok := set[0].Class == CLASS_IN && set[1].Class == CLASS_CH ||
		set[1].Class == CLASS_IN && set[0].Class == CLASS_CH

	if !ok {
		t.Fatal(40)
	}

	set.SetAdd(RRs{&RR{"example.com", TYPE_A, CLASS_IN, 0, &A{net.ParseIP("1.2.3.4")}}})
	if len(set) != 2 { // equal => 2 + 0
		t.Log(set)
		t.Fatal(50, len(set), "!= 2")
	}

	set.SetAdd(RRs{&RR{"example.com", TYPE_NS, CLASS_IN, 0, &NS{"ns.example.com"}}})
	if len(set) != 3 { // diff type => 2 + 1
		t.Log(set)
		t.Fatal(60, len(set), "!= 3")
	}

	set.SetAdd(RRs{&RR{"example.com", TYPE_NS, CLASS_IN, 0, &NS{"ns.example.com"}}})
	if len(set) != 3 { // eq => 3 + 0
		t.Log(set)
		t.Fatal(70, len(set), "!= 3")
	}

	set.SetAdd(RRs{&RR{"example.com", TYPE_NS, CLASS_IN, 0, &NS{"ns2.example.com"}}})
	if len(set) != 4 { // dif rdata => 3 + 1
		t.Log(set)
		t.Fatal(80, len(set), "!= 3")
	}
}

func TestPartition(t *testing.T) {
	data := RRs{
		&RR{"example.com", TYPE_A, CLASS_IN, 0,
			&A{net.ParseIP("1.2.3.4")}},
		&RR{"example.com", TYPE_A, CLASS_IN, 0,
			&A{net.ParseIP("2.2.3.4")}},
		&RR{"example.com", TYPE_AAAA, CLASS_IN, 0,
			&A{net.ParseIP("::1")}},
		&RR{"example.com", TYPE_AAAA, CLASS_IN, 0,
			&A{net.ParseIP("::2")}},
	}

	parts := data[:0].Partition(false)

	if len(parts) != 0 {
		t.Fatal(10, len(parts), 0)
	}

	parts = data[:1].Partition(false)
	if len(parts) != 1 {
		t.Fatal(20, len(parts), 1)
	}

	part := parts[data[0].Type]
	if len(part) != 1 {
		t.Fatal(30, len(part), 1)
	}

	if part[0] != data[0] {
		t.Fatal(40)
	}

	parts = data[:2].Partition(false)
	if len(parts) != 1 {
		t.Fatal(50, len(parts), 1)
	}

	part = parts[data[0].Type]
	if len(part) != 2 {
		t.Fatal(60, len(part), 2)
	}

	if !(part[0] == data[0] && part[1] == data[1] || part[0] == data[1] && part[1] == data[0]) {
		t.Fatal(70)
	}

	parts = data.Partition(false)
	if len(parts) != 2 {
		t.Fatal(80, len(parts), 2)
	}

	part = parts[data[0].Type]
	if len(part) != 2 {
		t.Fatal(80, len(part), 2)
	}

	if !(part[0] == data[0] && part[1] == data[1] || part[0] == data[1] && part[1] == data[0]) {
		t.Fatal(100)
	}

	part = parts[data[2].Type]
	if len(part) != 2 {
		t.Fatal(110, len(part), 2)
	}

	if !(part[0] == data[2] && part[1] == data[3] || part[0] == data[3] && part[1] == data[2]) {
		t.Fatal(120)
	}

}

func TestTreeAddGet(t *testing.T) {
	com := RRs{
		&RR{"example.com.", TYPE_A, CLASS_IN, 0,
			&A{net.ParseIP("1.2.3.4")}},
		&RR{"example.com.", TYPE_A, CLASS_IN, 0,
			&A{net.ParseIP("2.2.3.4")}},
	}
	org := RRs{
		&RR{"example.org.", TYPE_A, CLASS_IN, 0,
			&A{net.ParseIP("1.2.3.4")}},
		&RR{"example.org.", TYPE_A, CLASS_IN, 0,
			&A{net.ParseIP("2.2.3.4")}},
	}
	tr := NewTree()
	if get := tr.Get(com[0].Name); len(get) != 0 {
		t.Fatal(10, get)
	}

	if get := tr.Get(org[0].Name); len(get) != 0 {
		t.Fatal(20, get)
	}

	put := com[:1]
	tr.Add(put[0].Name, put, func(existing RRs) RRs {
		t.Fatal(30, existing)
		panic("unreachable")
	})

	get := tr.Get(put[0].Name)

	if len(get) != 1 {
		t.Fatal(50, get)
	}

	if !get[0].Equal(put[0]) {
		t.Fatalf("60 \ngot %s\nexp %s", get, put[0])
	}

	put = com[1:]
	flag := false

	tr.Add(put[0].Name, put, func(existing RRs) RRs {
		flag = true
		return append(existing, put...)
	})

	if !flag {
		t.Fatal(70)
	}

	get = tr.Get(put[0].Name)
	if len(get) != 2 {
		t.Fatal(80, get)
	}

	if !get[0].Equal(com[0]) {
		t.Fatalf("90 \ngot %s\nexp %s", get[0], com[0])
	}

	if !get[1].Equal(com[1]) {
		t.Fatalf("100 \ngot %s\nexp %s", get[1], com[1])
	}

	put = org[:1]
	tr.Add(put[0].Name, put, func(existing RRs) RRs {
		t.Fatal(110, existing)
		panic("unreachable")
	})

	get = tr.Get(put[0].Name)
	if len(get) != 1 {
		t.Fatal(130, get)
	}

	if !get[0].Equal(put[0]) {
		t.Fatalf("140 \ngot %s\nexp %s", get, put[0])
	}

	put = org[1:]
	flag = false

	tr.Add(put[0].Name, put, func(existing RRs) RRs {
		flag = true
		return append(existing, put...)
	})

	if !flag {
		t.Fatal(150)
	}

	get = tr.Get(put[0].Name)
	if len(get) != 2 {
		t.Fatal(160, get)
	}

	if !get[0].Equal(org[0]) {
		t.Fatalf("170 \ngot %s\nexp %s", get[0], org[0])
	}

	if !get[1].Equal(org[1]) {
		t.Fatalf("180 \ngot %s\nexp %s", get[1], org[1])
	}

	get = tr.Get(com[0].Name)
	if len(get) != 2 {
		t.Fatal(190, get)
	}

	if !get[0].Equal(com[0]) {
		t.Fatalf("200 \ngot %s\nexp %s", get[0], com[0])
	}

	if !get[1].Equal(com[1]) {
		t.Fatalf("210 \ngot %s\nexp %s", get[1], com[1])
	}

}

func TestTreeDelete(t *testing.T) {
	com := RRs{
		&RR{"example.com.", TYPE_A, CLASS_IN, 0,
			&A{net.ParseIP("1.2.3.4")}},
		&RR{"example.com.", TYPE_A, CLASS_IN, 0,
			&A{net.ParseIP("2.2.3.4")}},
	}
	org := RRs{
		&RR{"example.org.", TYPE_A, CLASS_IN, 0,
			&A{net.ParseIP("1.2.3.4")}},
		&RR{"example.org.", TYPE_A, CLASS_IN, 0,
			&A{net.ParseIP("2.2.3.4")}},
	}

	tr := NewTree()
	tr.Add(com[0].Name, com, nil)
	tr.Add(org[0].Name, org, nil)

	get := tr.Get(com[0].Name)
	if len(get) != 2 {
		t.Fatal(10, get)
	}

	get = tr.Get(org[0].Name)
	if len(get) != 2 {
		t.Fatal(20, get)
	}

	tr.Delete(com[0].Name)
	get = tr.Get(com[0].Name)
	if len(get) != 0 {
		t.Fatal(30, get)
	}

	get = tr.Get(org[0].Name)
	if len(get) != 2 {
		t.Fatal(40, get)
	}

	tr.Delete(org[0].Name)
	get = tr.Get(com[0].Name)
	if len(get) != 0 {
		t.Fatal(50, get)
	}

	get = tr.Get(org[0].Name)
	if len(get) != 0 {
		t.Fatal(60, get)
	}

}

func TestTreeEnum(t *testing.T) {
	com := RRs{
		&RR{"com.", TYPE_A, CLASS_IN, 0,
			&A{net.ParseIP("1.2.3.4")}},
		&RR{"com.", TYPE_AAAA, CLASS_IN, 0,
			&AAAA{net.ParseIP("::1")}},
	}
	org := RRs{
		&RR{"org.", TYPE_A, CLASS_IN, 0,
			&A{net.ParseIP("2.2.3.4")}},
	}

	tr := NewTree()
	tr.Add(com[0].Name, com, nil)
	tr.Add(org[0].Name, org, nil)

	tr.Enum(com[0].Name, func(path []string, data RRs) bool {
		for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
			path[i], path[j] = path[j], path[i]
		}
		pth := strings.Join(path, ".")
		if pth != com[0].Name {
			t.Fatalf("10 %q", pth)
		}

		if len(data) != 2 {
			t.Fatal(20)
		}
		return true
	})

	tr.Enum(org[0].Name, func(path []string, data RRs) bool {
		for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
			path[i], path[j] = path[j], path[i]
		}
		pth := strings.Join(path, ".")
		if pth != org[0].Name {
			t.Fatalf("30 %q", pth)
		}

		if len(data) != 1 {
			t.Fatal(40)
		}
		return true
	})

	c, o := false, false
	tr.Enum(".", func(path []string, data RRs) bool {
		for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
			path[i], path[j] = path[j], path[i]
		}
		pth := strings.Join(path, ".")

		switch {
		case pth == com[0].Name:
			if c {
				t.Fatal(50)
			}

			if len(data) != 2 {
				t.Fatal(60, data)
			}
			c = true
		case pth == org[0].Name:
			if o {
				t.Fatal(70)
			}
			if len(data) != 1 {
				t.Fatal(80, data)
			}
			o = true
		}

		return true
	})

	if !c {
		t.Fatal(90)
	}

	if !o {
		t.Fatal(100)
	}
}

func TestTreePut(t *testing.T) {
	com := RRs{
		&RR{"com.", TYPE_A, CLASS_IN, 0,
			&A{net.ParseIP("1.2.3.4")}},
		&RR{"com.", TYPE_AAAA, CLASS_IN, 0,
			&AAAA{net.ParseIP("::1")}},
	}

	tr := NewTree()

	tr.Put(com[0].Name, com[:1])
	get := tr.Get(com[0].Name)

	if len(get) != 1 {
		t.Fatal(10)
	}

	if !get[0].Equal(com[0]) {
		t.Fatal(20)
	}

	tr.Put(com[1].Name, com[1:])
	get = tr.Get(com[1].Name)

	if len(get) != 1 {
		t.Fatal(30)
	}

	if !get[0].Equal(com[1]) {
		t.Fatal(40)
	}

	tr.Put(com[0].Name, com)
	get = tr.Get(com[0].Name)

	if len(get) != 2 {
		t.Fatal(50)
	}

}
