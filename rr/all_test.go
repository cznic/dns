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
	"github.com/cznic/dns"
	"github.com/cznic/strutil"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
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
		&RR{"nDHCID.example.com.", TYPE_DHCID, CLASS_IN, -1,
			&DHCID{[]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}}},
		&RR{"nDLV.example.com.", TYPE_DLV, CLASS_IN, -1,
			&DLV{0x1234, 0x56, HashAlgorithmSHA1,
				[]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}}},
		&RR{"nDNAME.example.com.", TYPE_DNAME, CLASS_IN, -1,
			&DNAME{"dname.example.com."}},
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
		&RR{"nHIP.example.com.", TYPE_HIP, CLASS_IN, -1,
			&HIP{IPSECKEYAlgorithmRSA,
				[]byte{1, 3, 5, 7, 9},
				[]byte{11, 13, 15, 17, 19},
				nil,
			},
		},
		&RR{"nHIP.example.com.", TYPE_HIP, CLASS_IN, -1,
			&HIP{IPSECKEYAlgorithmRSA,
				[]byte{10, 30, 50, 70, 90, 99},
				[]byte{111, 113, 115, 117, 119, 101},
				[]string{"a.example.com."},
			},
		},
		&RR{"nHIP.example.com.", TYPE_HIP, CLASS_IN, -1,
			&HIP{IPSECKEYAlgorithmRSA,
				[]byte{11, 31, 51, 71, 91, 98, 97},
				[]byte{111, 131, 151, 171, 191, 102, 103},
				[]string{"a.example.com.", "b.example.com."},
			},
		},
		&RR{"nHIP.example.com.", TYPE_HIP, CLASS_IN, -1,
			&HIP{IPSECKEYAlgorithmRSA,
				[]byte{12, 32, 52, 72, 92, 96, 95, 94},
				[]byte{112, 132, 152, 172, 192, 104, 105, 106},
				[]string{"a.example.com.", "b.example.com.", "c.example.com."},
			},
		},
		&RR{"nIPSECKEY.example.com.", TYPE_IPSECKEY, CLASS_IN, -1,
			&IPSECKEY{10, GatewayNone, IPSECKEYAlgorithmRSA,
				nil,
				[]byte{13, 14, 15, 16}},
		},
		&RR{"nIPSECKEY.example.com.", TYPE_IPSECKEY, CLASS_IN, -1,
			&IPSECKEY{11, GatewayIPV4, IPSECKEYAlgorithmRSA,
				net.IPv4(1, 2, 3, 4),
				[]byte{12, 13, 14, 15, 16}},
		},
		&RR{"nIPSECKEY.example.com.", TYPE_IPSECKEY, CLASS_IN, -1,
			&IPSECKEY{11, GatewayIPV6, IPSECKEYAlgorithmRSA,
				net.ParseIP("2001:4860:0:2001::68"),
				[]byte{11, 12, 13, 14, 15, 16}},
		},
		&RR{"nIPSECKEY.example.com.", TYPE_IPSECKEY, CLASS_IN, -1,
			&IPSECKEY{11, GatewayDomain, IPSECKEYAlgorithmRSA,
				"gateway.example.com.",
				[]byte{10, 11, 12, 13, 14, 15, 16}},
		},
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
		&RR{"nNSEC.example.com.", TYPE_NSEC, CLASS_IN, -1,
			&NSEC{"next.example.com.",
				TypesEncode([]Type{TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_PTR})},
		},
		&RR{"nNSEC.example.com.", TYPE_NSEC, CLASS_IN, -1,
			&NSEC{"next.example.com.",
				TypesEncode([]Type{TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_PTR, Type(1234)})},
		},
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
		&RR{"nSPF.example.com.", TYPE_SPF, CLASS_IN, -1,
			&SPF{[]string{"spf the quick \" brown fox"}}},
		&RR{"nSPF.example.com.", TYPE_SPF, CLASS_IN, -1,
			&SPF{[]string{"spf the quick \" brown fox", "jumps over"}}},
		&RR{"nSPF.example.com.", TYPE_SPF, CLASS_IN, -1,
			&SPF{[]string{strings.Repeat("D", 254), strings.Repeat("E", 254), strings.Repeat("F", 254)}}},
		&RR{"nSRV.example.com.", TYPE_SRV, CLASS_IN, -1,
			&SRV{1, 2, 4, "y.example.com."}},
		&RR{"nSSHFP.example.com.", TYPE_SSHFP, CLASS_IN, -1,
			&SSHFP{SSHFPAlgorithmDSA, SSHFPTypeSHA1,
				[]byte{1, 2, 4, 8, 16, 32, 64, 128}},
		},
		&RR{"nTKEY.example.com.", TYPE_TKEY, CLASS_IN, -1,
			&TKEY{"SAMPLE-ALG0.EXAMPLE.",
				time.Now().Add(-time.Hour),
				time.Now().Add(time.Hour),
				TKEYModeReserved0,
				TSIG_BADSIG,
				nil,
				nil,
			},
		},
		&RR{"nTKEY.example.com.", TYPE_TKEY, CLASS_IN, -1,
			&TKEY{"SAMPLE-ALG1.EXAMPLE.",
				time.Now().Add(-time.Hour * 2),
				time.Now().Add(time.Hour * 2),
				TKEYModeServerAssignment,
				TKEY_BADMODE,
				[]byte{1, 2, 3, 4, 5},
				nil,
			},
		},
		&RR{"nTKEY.example.com.", TYPE_TKEY, CLASS_IN, -1,
			&TKEY{"SAMPLE-ALG2.EXAMPLE.",
				time.Now().Add(-time.Hour * 3),
				time.Now().Add(time.Hour * 3),
				TKEYModeDiffieHellmanExchange,
				TKEY_BADNAME,
				nil,
				[]byte{11, 21, 31, 41, 51},
			},
		},
		&RR{"nTKEY.example.com.", TYPE_TKEY, CLASS_IN, -1,
			&TKEY{"SAMPLE-ALG3.EXAMPLE.",
				time.Now().Add(-time.Hour * 4),
				time.Now().Add(time.Hour * 4),
				TKEYModeGSSAPINegotation,
				TKEY_BADLAG,
				[]byte{12, 22, 32, 42, 52},
				[]byte{13, 23, 33, 43, 53},
			},
		},
		&RR{"nTSIG.example.com.", TYPE_TSIG, CLASS_IN, -1,
			&TSIG{"SAMPLE-ALG.EXAMPLE.",
				time.Now(),
				time.Second * 300,
				[]byte{1, 2, 3, 4, 5, 6},
				12345,
				0,
				nil,
			},
		},
		&RR{"nTSIG.example.com.", TYPE_TSIG, CLASS_IN, -1,
			&TSIG{"SAMPLE-ALG2.EXAMPLE.",
				time.Now().Add(-time.Hour),
				time.Second * 431,
				[]byte{10, 20, 30, 40, 50, 60},
				54321,
				16,
				[]byte{11, 22, 33, 0xAA, 0xBB, 0xFF},
			},
		},
		&RR{"nTXT.example.com.", TYPE_TXT, CLASS_IN, -1,
			&TXT{[]string{"the quick \" brown fox"}}},
		&RR{"nTXT.example.com.", TYPE_TXT, CLASS_IN, -1,
			&TXT{[]string{"the quick \" brown fox", "jumps over"}}},
		&RR{"nTXT.example.com.", TYPE_TXT, CLASS_IN, -1,
			&TXT{[]string{strings.Repeat("A", 254), strings.Repeat("B", 254), strings.Repeat("C", 254)}}},
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
				t.Errorf("\ngot:\n%sexp:\n%s", hex.Dump([]byte(line2)), hex.Dump([]byte(line1)))
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

// RFC4701
func TestDHCID(t *testing.T) {

	// 3.6.1.  Example 1
	// 
	//    A DHCP server allocates the IPv6 address 2001:DB8::1234:5678 to a
	//    client that included the DHCPv6 client-identifier option data 00:01:
	//    00:06:41:2d:f1:66:01:02:03:04:05:06 in its DHCPv6 request.  The
	//    server updates the name "chi6.example.com" on the client's behalf and
	//    uses the DHCP client identifier option data as input in forming a
	//    DHCID RR.  The DHCID RDATA is formed by setting the two type octets
	//    to the value 0x0002, the 1-octet digest type to 1 for SHA-256, and
	//    performing a SHA-256 hash computation across a buffer containing the
	//    14 octets from the client-id option and the FQDN (represented as
	//    specified in Section 3.5).
	// 
	//      chi6.example.com.     AAAA    2001:DB8::1234:5678
	//      chi6.example.com.     DHCID   ( AAIBY2/AuCccgoJbsaxcQc9TUapptP69l
	//                                      OjxfNuVAA2kjEA= )
	// 
	//    If the DHCID RR type is not supported, the RDATA would be encoded
	//    [13] as:
	// 
	//      \# 35 ( 000201636fc0b8271c82825bb1ac5c41cf5351aa69b4febd94e8f17cd
	//             b95000da48c40 )

	rd := &DHCID{}
	dhcid := &RR{"chi6.example.com.", TYPE_DHCID, CLASS_IN, 100, rd}
	rd.SetData(
		2, // Identifier type
		[]byte{ // DHCPv6 client-identifier option data
			0x00, 0x01, 0x00, 0x06, 0x41, 0x2d, 0xf1, 0x66, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		},
		"chi6.example.com.",
	)
	t.Log(dhcid)
	if g, e := string(strutil.Base64Encode(rd.Data)), "AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA="; g != e {
		t.Errorf("\ngot: %q\nexp: %q", g, e)
	}

	// 3.6.2.  Example 2
	// 
	//    A DHCP server allocates the IPv4 address 192.0.2.2 to a client that
	//    included the DHCP client-identifier option data 01:07:08:09:0a:0b:0c
	//    in its DHCP request.  The server updates the name "chi.example.com"
	//    on the client's behalf and uses the DHCP client identifier option
	//    data as input in forming a DHCID RR.  The DHCID RDATA is formed by
	//    setting the two type octets to the value 0x0001, the 1-octet digest
	//    type to 1 for SHA-256, and performing a SHA-256 hash computation
	//    across a buffer containing the seven octets from the client-id option
	//    and the FQDN (represented as specified in Section 3.5).
	// 
	//      chi.example.com.      A       192.0.2.2
	//      chi.example.com.      DHCID   ( AAEBOSD+XR3Os/0LozeXVqcNc7FwCfQdW
	//                                      L3b/NaiUDlW2No= )
	// 
	//    If the DHCID RR type is not supported, the RDATA would be encoded
	//    [13] as:
	// 
	//      \# 35 ( 0001013920fe5d1dceb3fd0ba3379756a70d73b17009f41d58bddbfcd
	//              6a2503956d8da )

	rd = &DHCID{}
	dhcid = &RR{"chi.example.com.", TYPE_DHCID, CLASS_IN, 100, rd}
	rd.SetData(
		1, // Identifier type
		[]byte{ // DHCP client-identifier option data
			0x01, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
		},
		"chi.example.com.",
	)
	t.Log(dhcid)
	if g, e := string(strutil.Base64Encode(rd.Data)), "AAEBOSD+XR3Os/0LozeXVqcNc7FwCfQdWL3b/NaiUDlW2No="; g != e {
		t.Errorf("\ngot: %q\nexp: %q", g, e)
	}

	// 3.6.3.  Example 3
	// 
	//    A DHCP server allocating the IPv4 address 192.0.2.3 to a client with
	//    the Ethernet MAC address 01:02:03:04:05:06 using domain name
	//    "client.example.com" uses the client's link-layer address to identify
	//    the client.  The DHCID RDATA is composed by setting the two type
	//    octets to zero, the 1-octet digest type to 1 for SHA-256, and
	//    performing an SHA-256 hash computation across a buffer containing the
	//    1-octet 'htype' value for Ethernet, 0x01, followed by the six octets
	//    of the Ethernet MAC address, and the domain name (represented as
	//    specified in Section 3.5).
	// 
	//      client.example.com.   A       192.0.2.3
	//      client.example.com.   DHCID   ( AAABxLmlskllE0MVjd57zHcWmEH3pCQ6V
	//                                      ytcKD//7es/deY= )
	// 
	//    If the DHCID RR type is not supported, the RDATA would be encoded
	//    [13] as:
	// 
	//      \# 35 ( 000001c4b9a5b249651343158dde7bcc77169841f7a4243a572b5c283
	//              fffedeb3f75e6 )

	rd = &DHCID{}
	dhcid = &RR{"client.example.com.", TYPE_DHCID, CLASS_IN, 100, rd}
	rd.SetData(
		0, // Identifier type
		[]byte{0x01, // htype
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // MAC
		},
		"client.example.com.",
	)
	t.Log(dhcid)
	if g, e := string(strutil.Base64Encode(rd.Data)), "AAABxLmlskllE0MVjd57zHcWmEH3pCQ6VytcKD//7es/deY="; g != e {
		t.Errorf("\ngot: %q\nexp: %q", g, e)
	}
}

func TestTSIG(t *testing.T) {
	// http://tools.ietf.org/html/rfc2845 3.2
	//
	// Field Name    Value       Wire Format         Meaning
	// ----------------------------------------------------------------------
	// Time Signed   853804800   00 00 32 e4 07 00   Tue Jan 21 00:00:00 1997
	// Fudge         300         01 2C               5 minutes

	const (
		mac   = "MAC"
		other = "OTHER"
	)
	ts := time.Date(1997, 1, 21, 0, 0, 0, 0, time.UTC)
	fudge := time.Second * 300
	tsig := &TSIG{"X.", ts, fudge, []byte(mac), 0x1234, 0x11, []byte(other)}
	w := dns.NewWirebuf()
	tsig.Encode(w)
	t.Logf("\n%s", hex.Dump(w.Buf))
	if g, e := len(w.Buf), 27; g != e {
		t.Fatalf("%d != %d", g, e)
	}

	if g, e := w.Buf, []byte{
		0x01, 'X', 0x00,
		0x00, 0x00, 0x32, 0xe4, 0x07, 0x00,
		0x01, 0x2c,
		0x00, 0x03, 'M', 'A', 'C',
		0x12, 0x34,
		0x00, 0x11,
		0x00, 0x05, 'O', 'T', 'H', 'E', 'R',
	}; !bytes.Equal(g, e) {
		t.Errorf("\n%s\n!=\n%s", hex.Dump(g), hex.Dump(e))
	}

	tsig2 := &TSIG{}
	p := 0
	if err := tsig2.Decode(w.Buf, &p, nil); err != nil {
		t.Fatal(err)
	}

	if g, e := p, 27; g != e {
		t.Fatalf("%d != %d", g, e)
	}

	if g, e := tsig2.String(), tsig.String(); g != e {
		t.Errorf("\n%v\n!=\n%v", g, e)
	}
}
