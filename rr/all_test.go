// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

package rr

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"testing"
)

var optDev = flag.Bool("dev", false, "enable dev helpers")

func init() {
	flag.Parse()
}

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

func TestLOC(t *testing.T) {
	loc := &LOC{}
	var i int64
	for i = -10000000; i <= 4284967295; i += 1000000 {
		loc.EncAlt(i)
		if g, e := loc.DecAlt(), i; g != e {
			t.Fatalf("%d != %d", g, e)
		}
	}

	for deg := 0; deg <= 90; deg++ {
		min := rand.Intn(60)
		secs := rand.Intn(60000)
		positive := rand.Intn(100)&1 != 0
		x := loc.EncDMTS(deg, min, secs, positive)
		gd, gm, gs, gp := loc.DecDMTS(x)
		if gd != deg || gm != min || gs != secs || gp != positive {
			t.Logf("x: %d", x)
			t.Fatalf(
				"%d %d %d %t -> %d %d %d %t",
				deg, min, secs, positive,
				gd, gm, gs, gp,
			)
		}
	}
}

func Test0(t *testing.T) {
	loc := &LOC{}
	loc.Size = loc.EncPrec(123)                    // 1m
	loc.HorizPre = loc.EncPrec(4567)               // 40m
	loc.VertPre = loc.EncPrec(789012)              // 7000m
	loc.Latitude = loc.EncDMTS(1, 2, 3456, true)   // 1 2 3.456 N
	loc.Longitude = loc.EncDMTS(2, 3, 4567, false) // 2 3 4.567 W
	loc.EncAlt(-34567)                             // -345.67 m
	data := RRs{
		&RR{"nA.example.com.", TYPE_A, CLASS_IN, -1,
			&A{net.ParseIP("1.2.3.4")}},
		&RR{"nAAAA.example.com.", TYPE_AAAA, CLASS_IN, -1,
			&AAAA{net.ParseIP("::1")}},
		&RR{"nAFSDB.example.com.", TYPE_AFSDB, CLASS_IN, -1,
			&AFSDB{12345, "exchange.example.com."}},
		&RR{"nCNAME.example.com.", TYPE_CNAME, CLASS_IN, -1,
			&CNAME{"cname.example.com."}},
		&RR{"nCERT.example.com.", TYPE_CERT, CLASS_IN, -1,
			&CERT{CertPKIX, 0x1234, AlgorithmDSA_SHA1,
				[]byte{0, 6, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03}},
		},
		&RR{"nDNSKEY.example.com.", TYPE_DNSKEY, CLASS_IN, -1,
			&DNSKEY{2, 3, 4,
				[]byte{11, 12, 13, 14, 15, 16, 17, 18, 19}}},
		&RR{"nDS.example.com.", TYPE_DS, CLASS_IN, -1,
			&DS{0x1234, 0x56, HashAlgorithmSHA1,
				[]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}}},
		&RR{"nGPOS.example.com.", TYPE_GPOS, CLASS_IN, -1,
			&GPOS{-32.6882, 116.8652, 10.0}},
		&RR{"nHINFO.example.com.", TYPE_HINFO, CLASS_IN, -1,
			&HINFO{"x86_64", "Linux"}},
		&RR{"nISDN.example.com.", TYPE_ISDN, CLASS_IN, -1,
			&ISDN{"\"isdn", "\"sa"}},
		&RR{"nKEY.example.com.", TYPE_KEY, CLASS_IN, -1,
			&KEY{2, 3, 4,
				[]byte{11, 12, 13, 14, 15, 16, 17, 18, 19}}},
		&RR{"nKX.example.com.", TYPE_KX, CLASS_IN, -1,
			&KX{0x1234, "exchanger.example.com."}},
		&RR{"nLOC.example.com.", TYPE_LOC, CLASS_IN, -1,
			loc},
		&RR{"nMB.example.com.", TYPE_MB, CLASS_IN, -1,
			&MB{"exchange.example.com."}},
		&RR{"nMD.example.com.", TYPE_MD, CLASS_IN, -1,
			&MD{"exchange.example.com."}},
		&RR{"nMF.example.com.", TYPE_MF, CLASS_IN, -1,
			&MF{"exchange.example.com."}},
		&RR{"nMG.example.com.", TYPE_MG, CLASS_IN, -1,
			&MG{"exchange.example.com."}},
		&RR{"nMINFO.example.com.", TYPE_MINFO, CLASS_IN, -1,
			&MINFO{"a.example.com.", "b.example.com."}},
		&RR{"nMR.example.com.", TYPE_MR, CLASS_IN, -1,
			&MR{"exchange.example.com."}},
		&RR{"nMX.example.com.", TYPE_MX, CLASS_IN, -1,
			&MX{0x1234, "exchange.example.com."}},
		&RR{"nNAPTR.example.com.", TYPE_NAPTR, CLASS_IN, -1,
			&NAPTR{1, 2, "U", "E2U+sip", "!^.*$!sip:customer-service@example.com!", "."}},
		&RR{"nNS.example.com.", TYPE_NS, CLASS_IN, -1,
			&NS{"ns.example.com."}},
		&RR{"nNSAP.example.com.", TYPE_NSAP, CLASS_IN, -1,
			&NSAP{[]byte{1, 2, 3}}},
		&RR{"nNSAP-PTR.example.com.", TYPE_NSAP_PTR, CLASS_IN, -1,
			&NSAP_PTR{"cname.example.com."}},
		&RR{"nNSEC3.example.com.", TYPE_NSEC3, CLASS_IN, -1,
			&NSEC3{
				NSEC3PARAM{0x01, 0x02, 0x0304, []byte{11, 12, 13, 14, 15, 16, 17, 18, 19}},
				[]byte{1, 3, 5, 7, 11},
				[]byte{0, 6, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03},
			}},
		&RR{"nNSEC3PARAM.example.com.", TYPE_NSEC3PARAM, CLASS_IN, -1,
			&NSEC3PARAM{0x01, 0x02, 0x0304, []byte{11, 12, 13, 14, 15, 16, 17, 18, 19}}},
		&RR{"nNULL.example.com.", TYPE_NULL, CLASS_IN, -1,
			&NULL{[]byte{}}},
		&RR{"nNULL.example.com.", TYPE_NULL, CLASS_IN, -1,
			&NULL{[]byte{3, 7, 31, 127}}},
		&RR{"nOPT.example.com.", TYPE_OPT, Class(4096), -1,
			&OPT{}},
		&RR{"nOPT.example.com.", TYPE_OPT, Class(4096), -1,
			&OPT{[]OPT_DATA{{1, []byte{1, 2, 3, 4}}}}},
		&RR{"nOPT.example.com.", TYPE_OPT, Class(4096), -1,
			&OPT{[]OPT_DATA{{1, []byte{1, 2, 3, 4}}, {5, []byte{6, 7}}}}},
		&RR{"nPTR.example.com.", TYPE_PTR, CLASS_IN, -1,
			&PTR{"ptr.example.com."}},
		&RR{"nPX.example.com.", TYPE_PX, CLASS_IN, -1,
			&PX{0x1234, "exchange.example.com.", "px.example.com."}},
		&RR{"nRP.example.com.", TYPE_RP, CLASS_IN, -1,
			&RP{"a.example.com.", "b.example.com."}},
		&RR{"nRRSIG.example.com.", TYPE_RRSIG, CLASS_IN, -1,
			&RRSIG{TYPE_A, AlgorithmDSA_SHA1, 2, 3, 0x87654321, 0x12345678, 0x1234, "signer.example.com.",
				[]byte{0, 6, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03}},
		},
		&RR{"nRT.example.com.", TYPE_RT, CLASS_IN, -1,
			&RT{12345, "exchange.example.com."}},
		&RR{"nSIG.example.com.", TYPE_SIG, CLASS_IN, -1,
			&SIG{TYPE_A, AlgorithmDSA_SHA1, 2, 3, 0x87654321, 0x12345678, 0x1234, "signer.example.com.",
				[]byte{0, 6, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03}},
		},
		&RR{"nSOA.example.com.", TYPE_SOA, CLASS_IN, -1,
			&SOA{"mname.example.com.", "rname.example.com.", 0x12345678, 0x123456, 0x98765, 0x1331, 0x9812}},
		&RR{"nSRV.example.com.", TYPE_SRV, CLASS_IN, -1,
			&SRV{1, 2, 4, "y.example.com."}},
		&RR{"nTXT.example.com.", TYPE_TXT, CLASS_IN, -1,
			&TXT{"the quick \" brown fox"}},
		&RR{"nWKS.example.com.", TYPE_WKS, CLASS_IN, -1,
			&WKS{net.ParseIP("1.2.3.4"), UDP_Protocol, map[IP_Port]struct{}{}}},
		&RR{"nWKS.example.com.", TYPE_WKS, CLASS_IN, -1,
			&WKS{net.ParseIP("8.9.10.11"), TCP_Protocol, map[IP_Port]struct{}{SMTP_Port: struct{}{}}}},
		&RR{"nX25.example.com.", TYPE_X25, CLASS_IN, -1,
			&X25{"Linux \"rulez!\""}},

		// keep last, it's a RR which can have rdlength == 0
		&RR{"nOPT.example.com.", TYPE_OPT, Class(4096), -1,
			&OPT{}},
	}

	for i, r := range data {
		r.TTL = int32(i)
	}
	s := ""
	for _, r := range data {
		s += r.String() + "\n"
	}
	t.Logf("\n%s", s)

	var packed Bytes

	packed.Pack(data)
	t.Logf("packed bytes %d", len(packed))
	cmp := packed.Unpack()
	if g, e := len(cmp), len(data); g != e {
		t.Errorf("%d != %d", g, e)
	}

	s2 := ""
	for _, r := range cmp {
		s2 += r.String() + "\n"
	}
	t.Logf("\n%s", s2)
	if s2 != s {
		t.Errorf("string forms not equal")
		lines2, lines1 := strings.Split(s2, "\n"), strings.Split(s, "\n")
		for i, line2 := range lines2 {
			if line1 := lines1[i]; line2 != line1 {
				t.Errorf("g:\n%s\ne:\n%s", hex.Dump([]byte(line2)), hex.Dump([]byte(line1)))
				for j, c2 := range []byte(line2) {
					if j >= len(line1) {
						t.Errorf("len diff @ %d, %d != %d", j, len(line2), len(line1))
						break
					}
					if c1 := line1[j]; c2 != c1 {
						t.Errorf("@ 0x%x 0x%x != 0x%x", j, c2, c1)
						break
					}
				}
				t.Fatalf("line %d\ng:%q\ne:%q", i, line2, line1)
			}
		}
	}

	for i, r := range cmp {
		g, e := r.Name, "n"+r.Type.String()+".example.com."
		if g != e {
			t.Fatalf("%q != %q", g, e)
		}

		if int(r.TTL) != i {
			t.Fatal()
		}

		if r.Class != CLASS_IN && r.Type != TYPE_OPT {
			t.Fatal()
		}

		if g, e := fmt.Sprintf("%T", r.RData), fmt.Sprintf("%T", data[i].RData); g != e {
			t.Fatalf("%s != %s", g, e)
		}

		if g, e := r, data[i]; !g.Equal(e) {
			t.Fatalf("\n%s\n%s", g, e)
		}
	}

}

func TestEqual(t *testing.T) {
	a := &RR{"example.com", TYPE_A, CLASS_IN, 0, &A{net.ParseIP("1.2.3.4")}}
	if !a.Equal(a) { // a == a
		t.Fatal("false != true")
	}

	b := &RR{"example.com", TYPE_A, CLASS_IN, 1, &A{net.ParseIP("1.2.3.4")}}
	if !b.Equal(b) { // b == b
		t.Fatal("false != true")
	}

	if !a.Equal(b) { // a == b, TTL must be ignored
		t.Fatal("false != true")
	}

	b = &RR{"EXAMPLE.COM", TYPE_A, CLASS_IN, 1, &A{net.ParseIP("1.2.3.4")}}
	if !a.Equal(b) { // a == b, name case must be ignored
		t.Fatal("false != true")
	}

	b = &RR{"example.org", TYPE_A, CLASS_IN, 1, &A{net.ParseIP("1.2.3.4")}}
	if a.Equal(b) { // a != b, (name)
		t.Fatal("true != false")
	}

	b = &RR{"example.com", TYPE_AAAA, CLASS_IN, 1, &AAAA{net.ParseIP("1.2.3.4")}}
	if a.Equal(b) { // a != b (type)
		t.Fatal("true != false")
	}

	b = &RR{"example.com", TYPE_A, CLASS_CH, 1, &A{net.ParseIP("1.2.3.4")}}
	if a.Equal(b) { // a != b (class)
		t.Fatal("true != false")
	}

	b = &RR{"example.com", TYPE_A, CLASS_IN, 1, &A{net.ParseIP("1.2.3.5")}}
	if a.Equal(b) { // a != b (ip)
		t.Fatal("true != false")
	}

}

func TestSetAdd(t *testing.T) {
	set := RRs{}
	set.SetAdd(RRs{&RR{"example.com", TYPE_A, CLASS_IN, 0, &A{net.ParseIP("1.2.3.4")}}})
	if len(set) != 1 {
		t.Fatal(len(set), "!= 1")
	}

	if set[0].Name != "example.com" {
		t.Fatal(set[0].Name, "!= example.com")
	}

	set.SetAdd(RRs{&RR{"example.com", TYPE_A, CLASS_CH, 0, &A{net.ParseIP("1.2.3.4")}}})

	if len(set) != 2 { // dif class => 1 + 1
		t.Log(set)
		t.Fatal(len(set), "!= 2")
	}

	ok := set[0].Class == CLASS_IN && set[1].Class == CLASS_CH ||
		set[1].Class == CLASS_IN && set[0].Class == CLASS_CH

	if !ok {
		t.Fatal()
	}

	set.SetAdd(RRs{&RR{"example.com", TYPE_A, CLASS_IN, 0, &A{net.ParseIP("1.2.3.4")}}})
	if len(set) != 2 { // equal => 2 + 0
		t.Log(set)
		t.Fatal(len(set), "!= 2")
	}

	set.SetAdd(RRs{&RR{"example.com", TYPE_NS, CLASS_IN, 0, &NS{"ns.example.com"}}})
	if len(set) != 3 { // diff type => 2 + 1
		t.Log(set)
		t.Fatal(len(set), "!= 3")
	}

	set.SetAdd(RRs{&RR{"example.com", TYPE_NS, CLASS_IN, 0, &NS{"ns.example.com"}}})
	if len(set) != 3 { // eq => 3 + 0
		t.Log(set)
		t.Fatal(len(set), "!= 3")
	}

	set.SetAdd(RRs{&RR{"example.com", TYPE_NS, CLASS_IN, 0, &NS{"ns2.example.com"}}})
	if len(set) != 4 { // dif rdata => 3 + 1
		t.Log(set)
		t.Fatal(len(set), "!= 3")
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
		t.Fatal(len(parts), 0)
	}

	parts = data[:1].Partition(false)
	if len(parts) != 1 {
		t.Fatal(len(parts), 1)
	}

	part := parts[data[0].Type]
	if len(part) != 1 {
		t.Fatal(len(part), 1)
	}

	if part[0] != data[0] {
		t.Fatal()
	}

	parts = data[:2].Partition(false)
	if len(parts) != 1 {
		t.Fatal(len(parts), 1)
	}

	part = parts[data[0].Type]
	if len(part) != 2 {
		t.Fatal(len(part), 2)
	}

	if !(part[0] == data[0] && part[1] == data[1] || part[0] == data[1] && part[1] == data[0]) {
		t.Fatal()
	}

	parts = data.Partition(false)
	if len(parts) != 2 {
		t.Fatal(len(parts), 2)
	}

	part = parts[data[0].Type]
	if len(part) != 2 {
		t.Fatal(len(part), 2)
	}

	if !(part[0] == data[0] && part[1] == data[1] || part[0] == data[1] && part[1] == data[0]) {
		t.Fatal()
	}

	part = parts[data[2].Type]
	if len(part) != 2 {
		t.Fatal(len(part), 2)
	}

	if !(part[0] == data[2] && part[1] == data[3] || part[0] == data[3] && part[1] == data[2]) {
		t.Fatal()
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
		t.Fatal(get)
	}

	if get := tr.Get(org[0].Name); len(get) != 0 {
		t.Fatal(get)
	}

	put := com[:1]
	tr.Add(put[0].Name, put, func(existing RRs) RRs {
		t.Fatal(existing)
		panic("unreachable")
	})

	get := tr.Get(put[0].Name)

	if len(get) != 1 {
		t.Fatal(get)
	}

	if !get[0].Equal(put[0]) {
		t.Fatalf("\ngot %s\nexp %s", get, put[0])
	}

	put = com[1:]
	flag := false

	tr.Add(put[0].Name, put, func(existing RRs) RRs {
		flag = true
		return append(existing, put...)
	})

	if !flag {
		t.Fatal()
	}

	get = tr.Get(put[0].Name)
	if len(get) != 2 {
		t.Fatal(get)
	}

	if !get[0].Equal(com[0]) {
		t.Fatalf("\ngot %s\nexp %s", get[0], com[0])
	}

	if !get[1].Equal(com[1]) {
		t.Fatalf("\ngot %s\nexp %s", get[1], com[1])
	}

	put = org[:1]
	tr.Add(put[0].Name, put, func(existing RRs) RRs {
		t.Fatal(existing)
		panic("unreachable")
	})

	get = tr.Get(put[0].Name)
	if len(get) != 1 {
		t.Fatal(get)
	}

	if !get[0].Equal(put[0]) {
		t.Fatalf("\ngot %s\nexp %s", get, put[0])
	}

	put = org[1:]
	flag = false

	tr.Add(put[0].Name, put, func(existing RRs) RRs {
		flag = true
		return append(existing, put...)
	})

	if !flag {
		t.Fatal()
	}

	get = tr.Get(put[0].Name)
	if len(get) != 2 {
		t.Fatal(get)
	}

	if !get[0].Equal(org[0]) {
		t.Fatalf("\ngot %s\nexp %s", get[0], org[0])
	}

	if !get[1].Equal(org[1]) {
		t.Fatalf("\ngot %s\nexp %s", get[1], org[1])
	}

	get = tr.Get(com[0].Name)
	if len(get) != 2 {
		t.Fatal(get)
	}

	if !get[0].Equal(com[0]) {
		t.Fatalf("\ngot %s\nexp %s", get[0], com[0])
	}

	if !get[1].Equal(com[1]) {
		t.Fatalf("\ngot %s\nexp %s", get[1], com[1])
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
		t.Fatal(get)
	}

	get = tr.Get(org[0].Name)
	if len(get) != 2 {
		t.Fatal(get)
	}

	tr.Delete(com[0].Name)
	get = tr.Get(com[0].Name)
	if len(get) != 0 {
		t.Fatal(get)
	}

	get = tr.Get(org[0].Name)
	if len(get) != 2 {
		t.Fatal(get)
	}

	tr.Delete(org[0].Name)
	get = tr.Get(com[0].Name)
	if len(get) != 0 {
		t.Fatal(get)
	}

	get = tr.Get(org[0].Name)
	if len(get) != 0 {
		t.Fatal(get)
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
			t.Fatalf("%q", pth)
		}

		if len(data) != 2 {
			t.Fatal()
		}
		return true
	})

	tr.Enum(org[0].Name, func(path []string, data RRs) bool {
		for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
			path[i], path[j] = path[j], path[i]
		}
		pth := strings.Join(path, ".")
		if pth != org[0].Name {
			t.Fatalf("%q", pth)
		}

		if len(data) != 1 {
			t.Fatal()
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
				t.Fatal()
			}

			if len(data) != 2 {
				t.Fatal(data)
			}
			c = true
		case pth == org[0].Name:
			if o {
				t.Fatal()
			}
			if len(data) != 1 {
				t.Fatal(data)
			}
			o = true
		}

		return true
	})

	if !c {
		t.Fatal()
	}

	if !o {
		t.Fatal()
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
		t.Fatal()
	}

	if !get[0].Equal(com[0]) {
		t.Fatal()
	}

	tr.Put(com[1].Name, com[1:])
	get = tr.Get(com[1].Name)

	if len(get) != 1 {
		t.Fatal()
	}

	if !get[0].Equal(com[1]) {
		t.Fatal()
	}

	tr.Put(com[0].Name, com)
	get = tr.Get(com[0].Name)

	if len(get) != 2 {
		t.Fatal()
	}

}
