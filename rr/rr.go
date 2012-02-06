// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

// Package rr supports DNS resource records (RFC 1035 chapter 3.2).
package rr

import (
	"bytes"
	"github.com/cznic/dns"
	"github.com/cznic/strutil"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

const asserts = false

func init() {
	if asserts {
		println("WARNING: cznic/dns/rr - assertions enabled")
	}
}

const timeLayout = "20060201150405"

// A holds the zone A RData
type A struct {
	Address net.IP // A 32 bit Internet address.
}

// Implementation of dns.Wirer
func (d *A) Encode(b *dns.Wirebuf) {
	ip4(d.Address).Encode(b)
}

// Implementation of dns.Wirer
func (d *A) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*ip4)(&d.Address).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataA, d)
	}
	return
}

func (d *A) String() string {
	return d.Address.String()
}

// AAAA holds the zone AAAA RData
type AAAA struct {
	Address net.IP // A 128 bit Internet address.
}

// Implementation of dns.Wirer
func (d *AAAA) Encode(b *dns.Wirebuf) {
	ip6(d.Address).Encode(b)
}

// Implementation of dns.Wirer
func (d *AAAA) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*ip6)(&d.Address).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataAAAA, d)
	}
	return
}

func (d *AAAA) String() string {
	return d.Address.String()
}

// The AFS (originally the Andrew File System) system uses the DNS to map from
// a domain name to the name of an AFS cell database server.  The DCE Naming
// service uses the DNS for a similar function: mapping from the domain name of
// a cell to authenticated name servers for that cell.  The method uses a new
// RR type with mnemonic AFSDB and type code of 18 (decimal).
type AFSDB struct {
	// The <subtype> field is a 16 bit integer.
	SubType uint16
	// The <hostname> field is a domain name of a host that has a server
	// for the cell named by the owner name of the RR.
	Hostname string
}

// Implementation of dns.Wirer
func (d *AFSDB) Encode(b *dns.Wirebuf) {
	(dns.Octets2)(d.SubType).Encode(b)
	(dns.DomainName)(d.Hostname).Encode(b)
}

// Implementation of dns.Wirer
func (d *AFSDB) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&d.SubType).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.DomainName)(&d.Hostname).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataAFSDB, d)
	}
	return
}

func (d *AFSDB) String() string {
	return fmt.Sprintf("%d %s", d.SubType, d.Hostname)
}

// CNAME holds the zone CNAME RData
type CNAME struct {
	Name string
}

// Implementation of dns.Wirer
func (c CNAME) Encode(b *dns.Wirebuf) {
	(dns.DomainName)(c.Name).Encode(b)
}

// Implementation of dns.Wirer
func (c *CNAME) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&c.Name).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataCNAME, c)
	}
	return
}

func (c CNAME) String() string {
	return c.Name
}

// DNAME holds the zone DNAME RData
type DNAME struct {
	Name string
}

// Implementation of dns.Wirer
func (c DNAME) Encode(b *dns.Wirebuf) {
	(dns.DomainName)(c.Name).Encode(b)
}

// Implementation of dns.Wirer
func (c *DNAME) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&c.Name).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataDNAME, c)
	}
	return
}

func (c DNAME) String() string {
	return c.Name
}

// DNSSEC Algorithm Types
// 
// The DNSKEY, RRSIG, and DS RRs use an 8-bit number to identify the
// security algorithm being used.  These values are stored in the
// "Algorithm number" field in the resource record RDATA.
// 
// Some algorithms are usable only for zone signing (DNSSEC), some only
// for transaction security mechanisms (SIG(0) and TSIG), and some for
// both.  Those usable for zone signing may appear in DNSKEY, RRSIG, and
// DS RRs.  Those usable for transaction security would be present in
// SIG(0) and KEY RRs, as described in [RFC2931].
// 
//	                             Zone
//	Value Algorithm [Mnemonic]  Signing  References   Status
//	----- -------------------- --------- ----------  ---------
//	  0   reserved
//	  1   RSA/MD5 [RSAMD5]         n      [RFC2537]  NOT RECOMMENDED
//	  2   Diffie-Hellman [DH]      n      [RFC2539]   -
//	  3   DSA/SHA-1 [DSA]          y      [RFC2536]  OPTIONAL
//	  4   Elliptic Curve [ECC]              TBA       -
//	  5   RSA/SHA-1 [RSASHA1]      y      [RFC3110]  MANDATORY
//	252   Indirect [INDIRECT]      n                  -
//	253   Private [PRIVATEDNS]     y      see below  OPTIONAL
//	254   Private [PRIVATEOID]     y      see below  OPTIONAL
//	255   reserved
//	
//	6 - 251  Available for assignment by IETF Standards Action.
type AlgorithmType byte

// AlgorithmType values
const (
	AlgorithmReserved0 AlgorithmType = iota
	AlgorithmRSA_MD5
	AlgorithmDiffie_Hellman
	AlgorithmDSA_SHA1
	AlgorithmElliptic
	AlgorithmRSA_SHA1
	AlgorithmIndirect     AlgorithmType = 252
	AlgorithmPrivateDNS   AlgorithmType = 253
	AlgorithmPrivateOID   AlgorithmType = 254
	AlgorithmReserved1255 AlgorithmType = 255
)

// Class is a RR CLASS
type Class uint16

// Class values
const (
	CLASS_NONE Class = iota
	CLASS_IN         // the Internet
	CLASS_CS         // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
	CLASS_CH         // the CHAOS class
	CLASS_HS         // Hesiod
)

var classStr = map[Class]string{
	CLASS_NONE: "",
	CLASS_IN:   "IN",
	CLASS_CS:   "CS",
	CLASS_CH:   "CH",
	CLASS_HS:   "HS",
}

func (n Class) String() (s string) {
	var ok bool
	if s, ok = classStr[n]; !ok {
		return fmt.Sprintf("CLASS%d", uint16(n))
	}
	return
}

// Implementation of dns.Wirer
func (n Class) Encode(b *dns.Wirebuf) {
	dns.Octets2(n).Encode(b)
}

// Implementation of dns.Wirer
func (n *Class) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(n).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffClass, *n)
	}
	return
}

// DNSKEY holds the DNS key RData // RFC 4034
type DNSKEY struct {
	// Bit 7 of the Flags field is the Zone Key flag.  If bit 7 has value 1,
	// then the DNSKEY record holds a DNS zone key, and the DNSKEY RR's
	// owner name MUST be the name of a zone.  If bit 7 has value 0, then
	// the DNSKEY record holds some other type of DNS public key and MUST
	// NOT be used to verify RRSIGs that cover RRsets.
	// 
	// Bit 15 of the Flags field is the Secure Entry Point flag, described
	// in [RFC3757].  If bit 15 has value 1, then the DNSKEY record holds a
	// key intended for use as a secure entry point.  This flag is only
	// intended to be a hint to zone signing or debugging software as to the
	// intended use of this DNSKEY record; validators MUST NOT alter their
	// behavior during the signature validation process in any way based on
	// the setting of this bit.  This also means that a DNSKEY RR with the
	// SEP bit set would also need the Zone Key flag set in order to be able
	// to generate signatures legally.  A DNSKEY RR with the SEP set and the
	// Zone Key flag not set MUST NOT be used to verify RRSIGs that cover
	// RRsets.
	// 
	// Bits 0-6 and 8-14 are reserved: these bits MUST have value 0 upon
	// creation of the DNSKEY RR and MUST be ignored upon receipt.
	Flags uint16
	// The Protocol Field MUST have value 3, and the DNSKEY RR MUST be
	// treated as invalid during signature verification if it is found to be
	// some value other than 3.
	Protocol byte
	// The Algorithm field identifies the public key's cryptographic
	// algorithm and determines the format of the Public Key field.  A list
	// of DNSSEC algorithm types can be found in Appendix A.1
	Algorithm AlgorithmType
	// The Public Key Field holds the public key material.  The format
	// depends on the algorithm of the key being stored and is described in
	// separate documents.
	Key []byte
}

func NewDNSKEY(Flags uint16, Algorithm AlgorithmType, Key []byte) *DNSKEY {
	return &DNSKEY{Flags, 3, Algorithm, Key}
}

// Implementation of dns.Wirer
func (d *DNSKEY) Encode(b *dns.Wirebuf) {
	dns.Octets2(d.Flags).Encode(b)
	dns.Octet(d.Protocol).Encode(b)
	dns.Octet(d.Algorithm).Encode(b)
	b.Buf = append(b.Buf, d.Key...)
}

// Implementation of dns.Wirer
func (d *DNSKEY) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&d.Flags).Decode(b, pos, sniffer); err != nil {
		return
	}
	if err = (*dns.Octet)(&d.Protocol).Decode(b, pos, sniffer); err != nil {
		return
	}
	if err = (*dns.Octet)(&d.Algorithm).Decode(b, pos, sniffer); err != nil {
		return
	}
	n := len(b) - *pos
	if n <= 0 {
		return fmt.Errorf("(*DNSKEY).Decode: no key data")
	}
	d.Key = make([]byte, n)
	copy(d.Key, b[*pos:])
	*pos += n
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataDNSKEY, d)
	}
	return
}

func (d *DNSKEY) String() string {
	return fmt.Sprintf("%d %d %d %s", d.Flags, d.Protocol, d.Algorithm, strutil.Base64Encode(d.Key))
}

// The delegation signer (DS) resource record (RR) is inserted at a zone
// cut (i.e., a delegation point) to indicate that the delegated zone is
// digitally signed and that the delegated zone recognizes the indicated
// key as a valid zone key for the delegated zone. (RFC 3658)
type DS struct {
	// The key tag is calculated as specified in RFC 2535
	KeyTag uint16
	// Algorithm MUST be allowed to sign DNS data
	AlgorithmType
	// The digest type is an identifier for the digest algorithm used
	DigestType HashAlgorithm
	// The digest is calculated over the
	// canonical name of the delegated domain name followed by the whole
	// RDATA of the KEY record (all four fields)
	Digest []byte
}

// Implementation of dns.Wirer
func (d *DS) Encode(b *dns.Wirebuf) {
	dns.Octets2(d.KeyTag).Encode(b)
	dns.Octet(d.AlgorithmType).Encode(b)
	dns.Octet(d.DigestType).Encode(b)
	b.Buf = append(b.Buf, d.Digest...)
}

// Implementation of dns.Wirer
func (d *DS) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&d.KeyTag).Decode(b, pos, sniffer); err != nil {
		return
	}
	if err = (*dns.Octet)(&d.AlgorithmType).Decode(b, pos, sniffer); err != nil {
		return
	}
	if err = (*dns.Octet)(&d.DigestType).Decode(b, pos, sniffer); err != nil {
		return
	}
	var n int
	switch d.DigestType {
	case HashAlgorithmSHA1:
		n = 20
	default:
		return fmt.Errorf("unsupported digest type %d", d.DigestType)
	}

	end := *pos + n
	if end > len(b) {
		return fmt.Errorf("DS.Decode - buffer underflow")
	}
	d.Digest = append([]byte{}, b[*pos:end]...)
	*pos = end
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataDS, d)
	}
	return
}

func (d *DS) String() string {
	if asserts && len(d.Digest) == 0 {
		panic("internal error")
	}

	return fmt.Sprintf("%d %d %d %s", d.KeyTag, d.AlgorithmType, d.DigestType, hex.EncodeToString(d.Digest))
}

type ip4 net.IP

// Implementation of dns.Wirer
func (d ip4) Encode(b *dns.Wirebuf) {
	b4 := net.IP(d).To4()
	if asserts {
		if b4 == nil {
			panic(fmt.Errorf("%s is not an IPv4 address", net.IP(d)))
		}
	}
	b.Buf = append(b.Buf, b4...)
}

// Implementation of dns.Wirer
func (d *ip4) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p := *pos
	if p+4 > len(b) {
		return fmt.Errorf("ip4.Decode() - buffer underflow")
	}

	p0 := &b[p]
	*d = ip4(net.IPv4(b[p], b[p+1], b[p+2], b[p+3]))
	*pos = p + 4
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffIPV4, d)
	}
	return
}

type ip6 net.IP

// Implementation of dns.Wirer
func (d ip6) Encode(b *dns.Wirebuf) {
	b16 := net.IP(d).To16()
	if asserts {
		if b16 == nil {
			panic(fmt.Errorf("%s is not an IPv6 address", d))
		}
	}
	b.Buf = append(b.Buf, b16...)
}

// Implementation of dns.Wirer
func (d *ip6) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p := *pos
	if p+16 > len(b) {
		return fmt.Errorf("ip6.Decode() - buffer underflow")
	}

	p0 := &b[p]
	*d = make([]byte, 16)
	copy(*d, b[p:])
	*pos = p + 16
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffIPV6, d)
	}
	return
}

// The geographical location is defined with the mnemonic GPOS and type code
// 27.
//
// A floating point format was chosen to specify geographical locations for
// reasons of simplicity.  This also guarantees a concise unambiguous
// description of a location by enforcing three compulsory numerical values to
// be specified.
type GPOS struct {
	// The real number describing the longitude encoded as a printable
	// string. The precision is limited by 256 charcters within the range
	// -90..90 degrees. Positive numbers indicate locations north of the
	// equator.
	Longitude float64
	// The real number describing the latitude encoded as a printable
	// string. The precision is limited by 256 charcters within the range
	// -180..180 degrees. Positive numbers indicate locations east of the
	// prime meridian.
	Latitude float64
	// The real number describing the altitude (in meters) from mean
	// sea-level encoded as a printable string. The precision is limited by
	// 256 charcters. Positive numbers indicate locations above mean
	// sea-level.
	Altitude float64
}

// Implementation of dns.Wirer
func (d *GPOS) Encode(b *dns.Wirebuf) {
	var s dns.CharString
	s = dns.CharString(fmt.Sprintf("%f", d.Longitude))
	s.Encode(b)
	s = dns.CharString(fmt.Sprintf("%f", d.Latitude))
	s.Encode(b)
	s = dns.CharString(fmt.Sprintf("%f", d.Altitude))
	s.Encode(b)
}

// Implementation of dns.Wirer
func (d *GPOS) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	var s dns.CharString

	if err = s.Decode(b, pos, sniffer); err != nil {
		return
	}

	if _, err = fmt.Sscanf(string(s), "%f", &d.Longitude); err != nil {
		return
	}

	if err = s.Decode(b, pos, sniffer); err != nil {
		return
	}

	if _, err = fmt.Sscanf(string(s), "%f", &d.Latitude); err != nil {
		return
	}

	if err = s.Decode(b, pos, sniffer); err != nil {
		return
	}

	if _, err = fmt.Sscanf(string(s), "%f", &d.Altitude); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataGPOS, d)
	}
	return
}

func (d *GPOS) String() string {
	return fmt.Sprintf("%f %f %f", d.Longitude, d.Latitude, d.Altitude)
}

// HINFO records are used to acquire general information about a host.  The
// main use is for protocols such as FTP that can use special procedures when
// talking between machines or operating systems of the same type.
type HINFO struct {
	Cpu string // A <character-string> which specifies the CPU type.
	Os  string // A <character-string> which specifies the operating system type.
}

// Implementation of dns.Wirer
func (d *HINFO) Encode(b *dns.Wirebuf) {
	(dns.CharString)(d.Cpu).Encode(b)
	(dns.CharString)(d.Os).Encode(b)
}

// Implementation of dns.Wirer
func (d *HINFO) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.CharString)(&d.Cpu).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.CharString)(&d.Os).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataHINFO, d)
	}
	return
}

func (d *HINFO) String() string {
	return fmt.Sprintf(`"%s" "%s"`, strings.Replace(d.Cpu, `"`, `\"`, -1), strings.Replace(d.Os, `"`, `\"`, -1))
}

// An ISDN (Integrated Service Digital Network) number is simply a telephone
// number.  The intent of the members of the CCITT is to upgrade all telephone
// and data network service to a common service.
//
// The <ISDN-address> field is required; <sa> is optional.
type ISDN struct {
	// <ISDN-address> identifies the ISDN number of <owner> and DDI (Direct
	// Dial In) if any, as defined by E.164 [8] and E.163 [7], the ISDN and
	// PSTN (Public Switched Telephone Network) numbering plan.  E.163
	// defines the country codes, and E.164 the form of the addresses.  Its
	// format in master files is a <character-string> syntactically
	// identical to that used in TXT and HINFO.
	ISDN string
	// <sa> specifies the subaddress (SA).  The format of <sa> in master
	// files is a <character-string> syntactically identical to that used
	// in TXT and HINFO.
	Sa string
}

// Implementation of dns.Wirer
func (d *ISDN) Encode(b *dns.Wirebuf) {
	(dns.CharString)(d.ISDN).Encode(b)
	(dns.CharString)(d.Sa).Encode(b)
}

// Implementation of dns.Wirer
func (d *ISDN) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.CharString)(&d.ISDN).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.CharString)(&d.Sa).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataISDN, d)
	}
	return
}

func (d *ISDN) String() string {
	return fmt.Sprintf(`"%s" "%s"`, strings.Replace(d.ISDN, `"`, `\"`, -1), strings.Replace(d.Sa, `"`, `\"`, -1))
}

// The KEY resource record (RR) is used to store a public key that is
// associated with a Domain Name System (DNS) name.  This can be the public key
// of a zone, a user, or a host or other end entity. Security aware DNS
// implementations MUST be designed to handle at least two simultaneously valid
// keys of the same type associated with the same name.
//
// A KEY RR is, like any other RR, authenticated by a SIG RR.  KEY RRs must be
// signed by a zone level key.
type KEY struct {
	// Bit 7 of the Flags field is the Zone Key flag.  If bit 7 has value 1,
	// then the KEY record holds a DNS zone key, and the KEY RR's
	// owner name MUST be the name of a zone.  If bit 7 has value 0, then
	// the KEY record holds some other type of DNS public key and MUST
	// NOT be used to verify RRSIGs that cover RRsets.
	// 
	// Bit 15 of the Flags field is the Secure Entry Point flag, described
	// in [RFC3757].  If bit 15 has value 1, then the KEY record holds a
	// key intended for use as a secure entry point.  This flag is only
	// intended to be a hint to zone signing or debugging software as to the
	// intended use of this KEY record; validators MUST NOT alter their
	// behavior during the signature validation process in any way based on
	// the setting of this bit.  This also means that a KEY RR with the
	// SEP bit set would also need the Zone Key flag set in order to be able
	// to generate signatures legally.  A KEY RR with the SEP set and the
	// Zone Key flag not set MUST NOT be used to verify RRSIGs that cover
	// RRsets.
	// 
	// Bits 0-6 and 8-14 are reserved: these bits MUST have value 0 upon
	// creation of the KEY RR and MUST be ignored upon receipt.
	Flags uint16
	// The Protocol Field MUST have value 3, and the KEY RR MUST be
	// treated as invalid during signature verification if it is found to be
	// some value other than 3.
	Protocol byte
	// The Algorithm field identifies the public key's cryptographic
	// algorithm and determines the format of the Public Key field.  A list
	// of DNSSEC algorithm types can be found in Appendix A.1
	Algorithm AlgorithmType
	// The Public Key Field holds the public key material.  The format
	// depends on the algorithm of the key being stored and is described in
	// separate documents.
	Key []byte
}

func NewKEY(Flags uint16, Algorithm AlgorithmType, Key []byte) *KEY {
	return &KEY{Flags, 3, Algorithm, Key}
}

// Implementation of dns.Wirer
func (d *KEY) Encode(b *dns.Wirebuf) {
	dns.Octets2(d.Flags).Encode(b)
	dns.Octet(d.Protocol).Encode(b)
	dns.Octet(d.Algorithm).Encode(b)
	b.Buf = append(b.Buf, d.Key...)
}

// Implementation of dns.Wirer
func (d *KEY) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&d.Flags).Decode(b, pos, sniffer); err != nil {
		return
	}
	if err = (*dns.Octet)(&d.Protocol).Decode(b, pos, sniffer); err != nil {
		return
	}
	if err = (*dns.Octet)(&d.Algorithm).Decode(b, pos, sniffer); err != nil {
		return
	}
	n := len(b) - *pos
	if n <= 0 {
		return fmt.Errorf("(*KEY).Decode: no key data")
	}
	d.Key = make([]byte, n)
	copy(d.Key, b[*pos:])
	*pos += n
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataKEY, d)
	}
	return
}

func (d *KEY) String() string {
	return fmt.Sprintf("%d %d %d %s", d.Flags, d.Protocol, d.Algorithm, strutil.Base64Encode(d.Key))
}

// The LOC record is expressed in a master file in the following format:
//
//  <owner> <TTL> <class> LOC ( d1 [m1 [s1]] {"N"|"S"} d2 [m2 [s2]]
//                            {"E"|"W"} alt["m"] [siz["m"] [hp["m"]
//                            [vp["m"]]]] )
//
// (The parentheses are used for multi-line data as specified in [RFC 1035]
// section 5.1.)
//
// where:
//
//    d1:     [0 .. 90]            (degrees latitude)
//    d2:     [0 .. 180]           (degrees longitude)
//    m1, m2: [0 .. 59]            (minutes latitude/longitude)
//    s1, s2: [0 .. 59.999]        (seconds latitude/longitude)
//    alt:    [-100000.00 .. 42849672.95] BY .01 (altitude in meters)
//    siz, hp, vp: [0 .. 90000000.00] (size/precision in meters)
//
// If omitted, minutes and seconds default to zero, size defaults to 1m,
// horizontal precision defaults to 10000m, and vertical precision defaults to
// 10m.  These defaults are chosen to represent typical ZIP/postal code area
// sizes, since it is often easy to find approximate geographical location by
// ZIP/postal code.
type LOC struct {
	// Version number of the representation.  This must be zero.
	// Implementations are required to check this field and make no
	// assumptions about the format of unrecognized versions.
	Version byte
	// The diameter of a sphere enclosing the described entity, in
	// centimeters, expressed as a pair of four-bit unsigned integers, each
	// ranging from zero to nine, with the most significant four bits
	// representing the base and the second number representing the power
	// of ten by which to multiply the base.  This allows sizes from 0e0
	// (<1cm) to 9e9 (90,000km) to be expressed.  This representation was
	// chosen such that the hexadecimal representation can be read by eye;
	// 0x15 = 1e5.  Four-bit values greater than 9 are undefined, as are
	// values with a base of zero and a non-zero exponent.
	//
	// Since 20000000m (represented by the value 0x29) is greater than the
	// equatorial diameter of the WGS 84 ellipsoid (12756274m), it is
	// therefore suitable for use as a "worldwide" size.
	Size byte
	// The horizontal precision of the data, in centimeters, expressed
	// using the same representation as SIZE.  This is the diameter of the
	// horizontal "circle of error", rather than a "plus or minus" value.
	// (This was chosen to match the interpretation of SIZE; to get a "plus
	// or minus" value, divide by 2.)
	HorizPre byte
	// The vertical precision of the data, in centimeters, expressed using
	// the sane representation as for SIZE.  This is the total potential
	// vertical error, rather than a "plus or minus" value.  (This was
	// chosen to match the interpretation of SIZE; to get a "plus or minus"
	// value, divide by 2.)  Note that if altitude above or below sea level
	// is used as an approximation for altitude relative to the [WGS 84]
	// ellipsoid, the precision value should be adjusted.
	VertPre byte
	// The latitude of the center of the sphere described by the SIZE
	// field, expressed as a 32-bit integer, most significant octet first
	// (network standard byte order), in thousandths of a second of arc.
	// 2^31 represents the equator; numbers above that are north latitude.
	Latitude uint32
	// The longitude of the center of the sphere described by the SIZE
	// field, expressed as a 32-bit integer, most significant octet first
	// (network standard byte order), in thousandths of a second of arc,
	// rounded away from the prime meridian.  2^31 represents the prime
	// meridian; numbers above that are east longitude.
	Longitude uint32
	// The altitude of the center of the sphere described by the SIZE
	// field, expressed as a 32-bit integer, most significant octet first
	// (network standard byte order), in centimeters, from a base of
	// 100,000m below the [WGS 84] reference spheroid used by GPS
	// (semimajor axis a=6378137.0, reciprocal flattening
	// rf=298.257223563).  Altitude above (or below) sea level may be used
	// as an approximation of altitude relative to the the [WGS 84]
	// spheroid, though due to the Earth's surface not being a perfect
	// spheroid, there will be differences.  (For example, the geoid (which
	// sea level approximates) for the continental US ranges from 10 meters
	// to 50 meters below the [WGS 84] spheroid.  Adjustments to ALTITUDE
	// and/or VERT PRE will be necessary in most cases.  The Defense
	// Mapping Agency publishes geoid height values relative to the [WGS
	// 84] ellipsoid.
	Altitude uint32
}

// Implementation of dns.Wirer
func (d *LOC) Encode(b *dns.Wirebuf) {
	dns.Octet(d.Version).Encode(b)
	dns.Octet(d.Size).Encode(b)
	dns.Octet(d.HorizPre).Encode(b)
	dns.Octet(d.VertPre).Encode(b)
	dns.Octets4(d.Longitude).Encode(b)
	dns.Octets4(d.Latitude).Encode(b)
	dns.Octets4(d.Altitude).Encode(b)
}

// Implementation of dns.Wirer
func (d *LOC) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if (*dns.Octet)(&d.Version).Decode(b, pos, sniffer); err != nil {
		return
	}

	if (*dns.Octet)(&d.Size).Decode(b, pos, sniffer); err != nil {
		return
	}

	if (*dns.Octet)(&d.HorizPre).Decode(b, pos, sniffer); err != nil {
		return
	}

	if (*dns.Octet)(&d.VertPre).Decode(b, pos, sniffer); err != nil {
		return
	}

	if (*dns.Octets4)(&d.Longitude).Decode(b, pos, sniffer); err != nil {
		return
	}

	if (*dns.Octets4)(&d.Latitude).Decode(b, pos, sniffer); err != nil {
		return
	}

	if (*dns.Octets4)(&d.Altitude).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataLOC, d)
	}
	return
}

func (*LOC) Degrees(x uint32) (deg int) {
	f := int64(x) - (1 << 31)
	deg = int(f / (60 * 60 * 1000)) // 0.001 sec of arc
	return
}

func (*LOC) Minutes(x uint32) (min int) {
	f := int64(x) - (1 << 31)
	if f < 0 {
		f = -f
	}
	return int((f / (60000)) % 60)
}

func (*LOC) ThousandsSecs(x uint32) (ts int) {
	f := int64(x) - (1 << 31)
	if f < 0 {
		f = -f
	}
	return int(f % 60000)
}

func (d *LOC) DecAlt() (cm int64) {
	return int64(d.Altitude) - 10000000
}

func (d *LOC) EncAlt(cm int64) {
	d.Altitude = uint32(cm + 10000000)
}

func (d *LOC) DecDMTS(x uint32) (deg, min, ts int, positive bool) {
	deg = d.Degrees(x)
	if positive = deg >= 0; !positive {
		deg = -deg
	}
	min = d.Minutes(x)
	ts = d.ThousandsSecs(x)
	return
}

func (*LOC) EncDMTS(deg, min, ts int, positive bool) uint32 {
	x := int64(ts)
	x += int64(min) * 60000
	x += int64(deg) * 3600000
	switch positive {
	case true:
		x += 1 << 31
	case false:
		x = 1<<31 - x
	}
	return uint32(x)
}

var precs = [10]int64{
	1,
	10,
	100,
	1000,
	10000,
	100000,
	1000000,
	10000000,
	100000000,
	1000000000,
}

func (*LOC) DecPrec(x byte) (cm int64) {
	e := int(x & 15)
	if e > len(precs) {
		e = len(precs) - 1
	}
	return int64(x>>4) * precs[e]
}

func (*LOC) EncPrec(cm uint64) byte {
	var e byte
	var x uint64
	for e, x = 0, cm; x > 9; e, x = e+1, x/10 {
	}
	if e > 9 {
		e = 9
	}
	return byte(x<<4) | e
}

func (d *LOC) String() string {
	latDeg, latMin, latTS, north := d.DecDMTS(d.Latitude)
	lonDeg, lonMin, lonTS, east := d.DecDMTS(d.Longitude)
	altM := d.DecAlt()
	altCm := altM % 100
	if altCm < 0 {
		altCm = -altCm
	}
	sn := "S"
	if north {
		sn = "N"
	}
	we := "W"
	if east {
		we = "E"
	}
	siz, hp, vp := d.DecPrec(d.Size), d.DecPrec(d.HorizPre), d.DecPrec(d.VertPre)
	return fmt.Sprintf(
		"%d %d %d.%03d %s %d %d %d.%03d %s %d.%02dm %dm %dm %dm",
		latDeg, latMin, latTS/1000, latTS%1000, sn,
		lonDeg, lonMin, lonTS/1000, lonTS%1000, we,
		altM/100, altCm,
		siz/100, hp/100, vp/100,
	)
}

// MB records cause additional section processing which looks up an A type RRs
// corresponding to MADNAME.
type MB struct {
	// A <domain-name> which specifies a host which has the specified
	// mailbox.
	MADNAME string
}

// Implementation of dns.Wirer
func (d *MB) Encode(b *dns.Wirebuf) {
	dns.DomainName(d.MADNAME).Encode(b)
}

// Implementation of dns.Wirer
func (d *MB) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&d.MADNAME).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataMB, d)
	}
	return
}

func (d *MB) String() string {
	return d.MADNAME
}

// MD records cause additional section processing which looks up an A type
// record corresponding to MADNAME.
//
// MD is obsolete.  See the definition of MX and [RFC-974] for details of the
// new scheme.  The recommended policy for dealing with MD RRs found in a
// master file is to reject them, or to convert them to MX RRs with a
// preference of 0.
type MD struct {
	// A <domain-name> which specifies a host which has a mail agent for
	// the domain which should be able to deliver mail for the domain.
	MADNAME string
}

// Implementation of dns.Wirer
func (d *MD) Encode(b *dns.Wirebuf) {
	dns.DomainName(d.MADNAME).Encode(b)
}

// Implementation of dns.Wirer
func (d *MD) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&d.MADNAME).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataMD, d)
	}
	return
}

func (d *MD) String() string {
	return d.MADNAME
}

// MF records cause additional section processing which looks up an A type
// record corresponding to MADNAME.
//
// MF is obsolete.  See the definition of MX and [RFC-974] for details ofw the
// new scheme.  The recommended policy for dealing with MD RRs found in a
// master file is to reject them, or to convert them to MX RRs with a
// preference of 10.
type MF struct {
	// A <domain-name> which specifies a host which has a mail agent for
	// the domain which will accept mail for forwarding to the domain.
	MADNAME string
}

// Implementation of dns.Wirer
func (d *MF) Encode(b *dns.Wirebuf) {
	dns.DomainName(d.MADNAME).Encode(b)
}

// Implementation of dns.Wirer
func (d *MF) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&d.MADNAME).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataMF, d)
	}
	return
}

func (d *MF) String() string {
	return d.MADNAME
}

// MG records cause no additional section processing.
type MG struct {
	// A <domain-name> which specifies a mailbox which is a member of the
	// mail group specified by the domain name.
	MGNAME string
}

// Implementation of dns.Wirer
func (d *MG) Encode(b *dns.Wirebuf) {
	dns.DomainName(d.MGNAME).Encode(b)
}

// Implementation of dns.Wirer
func (d *MG) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&d.MGNAME).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataMG, d)
	}
	return
}

func (d *MG) String() string {
	return d.MGNAME
}

// MINFO records cause no additional section processing.  Although these
// records can be associated with a simple mailbox, they are usually used with
// a mailing list.
type MINFO struct {
	// A <domain-name> which specifies a mailbox which is responsible for
	// the mailing list or mailbox.  If this domain name names the root,
	// the owner of the MINFO RR is responsible for itself.  Note that many
	// existing mailing lists use a mailbox X-request for the RMAILBX field
	// of mailing list X, e.g., Msgroup-request for Msgroup.  This field
	// provides a more general mechanism.
	RMAILBX string
	// A <domain-name> which specifies a mailbox which is to receive error
	// messages related to the mailing list or mailbox specified by the
	// owner of the MINFO RR (similar to the ERRORS-TO: field which has
	// been proposed).  If this domain name names the root, errors should
	// be returned to the sender of the message.
	EMAILBX string
}

// Implementation of dns.Wirer
func (d *MINFO) Encode(b *dns.Wirebuf) {
	(dns.DomainName)(d.RMAILBX).Encode(b)
	(dns.DomainName)(d.EMAILBX).Encode(b)
}

// Implementation of dns.Wirer
func (d *MINFO) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&d.RMAILBX).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.DomainName)(&d.EMAILBX).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataMINFO, d)
	}
	return
}

func (d *MINFO) String() string {
	return fmt.Sprintf("%s %s", d.RMAILBX, d.EMAILBX)
}

// MR records cause no additional section processing.  The main use for MR is
// as a forwarding entry for a user who has moved to a different mailbox.
type MR struct {
	// A <domain-name> which specifies a mailbox which is the proper rename
	// of the specified mailbox.
	NEWNAME string
}

// Implementation of dns.Wirer
func (d *MR) Encode(b *dns.Wirebuf) {
	dns.DomainName(d.NEWNAME).Encode(b)
}

// Implementation of dns.Wirer
func (d *MR) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&d.NEWNAME).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataMR, d)
	}
	return
}

func (d *MR) String() string {
	return d.NEWNAME
}

// MX holds the zone MX RData
type MX struct {
	// A 16 bit integer which specifies the preference given to
	// this RR among others at the same owner.  Lower values
	// are preferred.
	Preference uint16
	// A <domain-name> which specifies a host willing to act as
	// a mail exchange for the owner name.
	Exchange string
}

// Implementation of dns.Wirer
func (d *MX) Encode(b *dns.Wirebuf) {
	dns.Octets2(d.Preference).Encode(b)
	dns.DomainName(d.Exchange).Encode(b)
}

// Implementation of dns.Wirer
func (d *MX) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&d.Preference).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.DomainName)(&d.Exchange).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataMX, d)
	}
	return
}

func (d *MX) String() string {
	return fmt.Sprintf("%d %s", d.Preference, d.Exchange)
}

// NODATA is used for negative caching of authoritative answers
// for queried non existent Type/Class combinations.
type NODATA struct {
	Type // The Type for which we are caching the NODATA
}

// Implementation of dns.Wirer
func (d *NODATA) Encode(b *dns.Wirebuf) {
	d.Type.Encode(b)
}

// Implementation of dns.Wirer
func (d *NODATA) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = d.Type.Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataNODATA, d)
	}
	return
}

func (d *NODATA) String() string {
	return fmt.Sprintf("%s", d.Type)
}

// NXDOMAIN is used for negative caching of authoritave answers 
// for queried non existing domain names.
type NXDOMAIN struct{}

// Implementation of dns.Wirer
func (d *NXDOMAIN) Encode(b *dns.Wirebuf) {
	// nop
}

// Implementation of dns.Wirer
func (d *NXDOMAIN) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	// nop
	return
}

func (d *NXDOMAIN) String() (s string) {
	// nop
	return
}

// NS holds the zone NS RData
type NS struct {
	// A <domain-name> which specifies a host which should be
	// authoritative for the specified class and domain.
	NSDName string
}

// Implementation of dns.Wirer
func (d *NS) Encode(b *dns.Wirebuf) {
	dns.DomainName(d.NSDName).Encode(b)
}

// Implementation of dns.Wirer
func (d *NS) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&d.NSDName).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataNS, d)
	}
	return
}

func (d *NS) String() string {
	return d.NSDName
}

// The NSAP RR is used to map from domain names to NSAPs. Name-to-NSAP mapping
// in the DNS using the NSAP RR operates analogously to IP address lookup. A
// query is generated by the resolver requesting an NSAP RR for a provided
// domain name.
//
// NSAP RRs conform to the top level RR format and semantics as defined in
// Section 3.2.1 of RFC 1035.
type NSAP struct {
	// A variable length string of octets containing the NSAP.  The value
	// is the binary encoding of the NSAP as it would appear in the CLNP
	// source or destination address field.
	NSAP []byte
}

// Implementation of dns.Wirer
func (d *NSAP) Encode(b *dns.Wirebuf) {
	b.Buf = append(b.Buf, d.NSAP...)
}

// Implementation of dns.Wirer
func (d *NSAP) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	if *pos >= len(b) {
		d.NSAP = []byte{}
		if sniffer != nil {
			sniffer(nil, nil, dns.SniffRDataNSAP, d)
		}
		return
	}

	p0 := &b[*pos]
	d.NSAP = append([]byte{}, b[*pos:]...)
	*pos = len(b)
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataNSAP, d)
	}
	return
}

func (d *NSAP) String() string {
	return fmt.Sprintf("0x%x", d.NSAP)
}

// NSAP_PTR has a function analogous to the PTR record used for IP addresses
type NSAP_PTR struct {
	Name string
}

// Implementation of dns.Wirer
func (c NSAP_PTR) Encode(b *dns.Wirebuf) {
	(dns.DomainName)(c.Name).Encode(b)
}

// Implementation of dns.Wirer
func (c *NSAP_PTR) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&c.Name).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataCNAME, c)
	}
	return
}

func (c NSAP_PTR) String() string {
	return c.Name
}

// HashAlgorithm is the type of the hash algorithm in the NSEC3 RR
type HashAlgorithm byte

// IANA registry for "DNSSEC NSEC3 Hash Algorithms".
// Values of HashAlgorithm.
const (
	HashAlgorithmReserved HashAlgorithm = iota
	HashAlgorithmSHA1
)

// The NSEC3 Resource Record (RR) provides authenticated denial of
// existence for DNS Resource Record Sets. (RFC 5155)
type NSEC3 struct {
	NSEC3PARAM
	// The Next Hashed Owner Name field contains the next hashed owner name
	// in hash order.  This value is in binary format.
	NextHashedOwnerName []byte
	// The Type Bit Maps field identifies the RRSet types that exist at the
	// original owner name of the NSEC3 RR
	TypeBitMaps []byte
}

// Implementation of dns.Wirer
func (d *NSEC3) Encode(b *dns.Wirebuf) {
	d.NSEC3PARAM.Encode(b)
	n := dns.Octets2(len(d.NextHashedOwnerName))
	n.Encode(b)
	b.Buf = append(b.Buf, d.NextHashedOwnerName...)
	b.Buf = append(b.Buf, d.TypeBitMaps...)
}

// Implementation of dns.Wirer
func (d *NSEC3) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = d.NSEC3PARAM.Decode(b, pos, sniffer); err != nil {
		return
	}

	var n dns.Octets2
	if err = n.Decode(b, pos, sniffer); err != nil {
		return
	}

	in := int(n)
	if *pos+in > len(b) {
		return fmt.Errorf("rr.*NSEC3.Decode - buffer underflow")
	}

	d.NextHashedOwnerName = append([]byte{}, b[*pos:*pos+in]...)
	*pos = *pos + in

	// here we (have to) rely on b being sliced exactly at the end of the wire format packet
	end := len(b)
	d.TypeBitMaps = append([]byte{}, b[*pos:end]...)
	*pos = end
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataNSEC3, d)
	}
	return
}

func (d *NSEC3) String() string {
	types, err := TypesDecode(d.TypeBitMaps)
	if err != nil {
		panic(err)
	}

	return fmt.Sprintf("%s %s %s", d.NSEC3PARAM.String(), strutil.Base32ExtEncode(d.NextHashedOwnerName), TypesString(types))
}

// The NSEC3PARAM RR contains the NSEC3 parameters (hash algorithm,
// flags, iterations, and salt) needed by authoritative servers to
// calculate hashed owner names. (RFC 5155)
type NSEC3PARAM struct {
	// The Hash Algorithm field identifies the cryptographic hash algorithm
	// used to construct the hash-value.
	HashAlgorithm
	// The Flags field contains 8 one-bit flags that can be used to indicate
	// different processing.  All undefined flags must be zero.  The only
	// flag defined by this specification is the Opt-Out flag.
	Flags byte
	// The Iterations field defines the number of additional times the hash
	// function has been performed.
	Iterations uint16
	// The Salt field is appended to the original owner name before hashing
	// in order to defend against pre-calculated dictionary attacks
	Salt []byte
	// The Hash Length field defines the length of the Next Hashed Owner
	// Name field, ranging in value from 1 to 255 octets
}

// Implementation of dns.Wirer
func (d *NSEC3PARAM) Encode(b *dns.Wirebuf) {
	dns.Octet(d.HashAlgorithm).Encode(b)
	dns.Octet(d.Flags).Encode(b)
	dns.Octets2(d.Iterations).Encode(b)
	if asserts && len(d.Salt) > 255 {
		panic("internal error")
	}
	dns.Octet(len(d.Salt)).Encode(b)
	b.Buf = append(b.Buf, d.Salt...)
}

// Implementation of dns.Wirer
func (d *NSEC3PARAM) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octet)(&d.HashAlgorithm).Decode(b, pos, sniffer); err != nil {
		return
	}
	if err = (*dns.Octet)(&d.Flags).Decode(b, pos, sniffer); err != nil {
		return
	}
	if err = (*dns.Octets2)(&d.Iterations).Decode(b, pos, sniffer); err != nil {
		return
	}
	var n byte
	if err = (*dns.Octet)(&n).Decode(b, pos, sniffer); err != nil {
		return
	}
	p := *pos
	next := p + int(n)
	if next > len(b) {
		return fmt.Errorf("NSEC3PARAM.Decode() - buffer underflow")
	}
	d.Salt = append([]byte{}, b[p:next]...)
	*pos = next
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataNSEC3PARAM, d)
	}
	return
}

func (d *NSEC3PARAM) String() string {
	s := hex.EncodeToString(d.Salt)
	if s == "" {
		s = "-"
	}
	return fmt.Sprintf("%d %d %d %s", d.HashAlgorithm, d.Flags, d.Iterations, s)
}

type NULL struct {
	Data []byte
}

// Implementation of dns.Wirer
func (d *NULL) Encode(b *dns.Wirebuf) {
	b.Buf = append(b.Buf, d.Data...)
}

// Implementation of dns.Wirer
func (d *NULL) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	n := 0
	var p0 *byte
	if *pos < len(b) {
		p0 = &b[*pos]
		n = len(b) - *pos
		d.Data = make([]byte, n)
		copy(d.Data, b[*pos:])
	} else {
		d.Data = []byte{}
		if sniffer != nil {
			sniffer(nil, nil, dns.SniffRDataNULL, d)
		}
		return
	}

	*pos += n
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataNULL, d)
	}
	return
}

func (d *NULL) String() string {
	if len(d.Data) == 0 {
		return "\\#"
	}

	return fmt.Sprintf("\\# %d %x", len(d.Data), d.Data)
}

// OPT_DATA holds an {attribute, value} pair of the OPT RR
type OPT_DATA struct {
	Code uint16
	Data []byte
}

// Implementation of dns.Wirer
func (d *OPT_DATA) Encode(b *dns.Wirebuf) {
	dns.Octets2(d.Code).Encode(b)
	dns.Octets2(len(d.Data)).Encode(b)
	b.Buf = append(b.Buf, d.Data...)
}

// Implementation of dns.Wirer
func (d *OPT_DATA) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&d.Code).Decode(b, pos, sniffer); err != nil {
		return
	}
	var n dns.Octets2
	if err = n.Decode(b, pos, sniffer); err != nil {
		return
	}
	p := *pos
	next := p + int(n)
	if next > len(b) {
		return fmt.Errorf("OPT_DATA.Decode() - buffer underflow")
	}
	d.Data = b[p:next]
	*pos = next
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffOPT_DATA, d)
	}
	return
}

func (d *OPT_DATA) String() string {
	return fmt.Sprintf("%04x:% x", d.Code, d.Data)
}

// OPT holds the RFC2671 OPT pseudo RR RData
type OPT struct {
	Values []OPT_DATA
}

// Implementation of dns.Wirer
func (d *OPT) Encode(b *dns.Wirebuf) {
	for _, v := range d.Values {
		v.Encode(b)
	}
}

// Implementation of dns.Wirer
func (d *OPT) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	for *pos < len(b) {
		v := OPT_DATA{}
		if err = v.Decode(b, pos, sniffer); err != nil {
			return
		}

		d.Values = append(d.Values, v)
	}
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataOPT, d)
	}
	return
}

func (d *OPT) String() string {
	a := make([]string, len(d.Values))
	for i, v := range d.Values {
		a[i] = v.String()
	}
	return strings.Join(a, " ")
}

// EXT_RCODE type holds the EDNS extended RCODE (in the RR.TTL field)
type EXT_RCODE struct {
	RCODE   byte
	Version byte
	Z       uint16
}

// FromTTL sets up the fields of EXT_RCODE from an int32 value (as is e.g. RR.TTL)
func (d *EXT_RCODE) FromTTL(n int32) {
	d.RCODE = byte(n >> 24)
	d.Version = byte(n >> 16)
	d.Z = uint16(n)
}

// ToTTL returns d as the value of a RR.TTL
func (d *EXT_RCODE) ToTTL() int32 {
	return int32(d.RCODE)<<24 | int32(d.Version)<<16 | int32(d.Z)
}

// Implementation of dns.Wirer
func (d *EXT_RCODE) Encode(b *dns.Wirebuf) {
	n := dns.Octets4(uint32(d.RCODE<<24) | uint32(d.Version<<16) | uint32(d.Z))
	n.Encode(b)
}

// Implementation of dns.Wirer
func (d *EXT_RCODE) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	var n dns.Octets4
	if err = n.Decode(b, pos, sniffer); err != nil {
		return
	}
	d.FromTTL(int32(n))
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffEXT_RCODE, d)
	}
	return
}

func (d *EXT_RCODE) String() string {
	return fmt.Sprintf("EXT_RCODE:%02xx Ver:%d Z:%d", d.RCODE, d.Version, d.Z)
}

// PTR holds the zone PTR RData
type PTR struct {
	// A <domain-name> which points to some location in the
	// domain name space.
	PTRDName string
}

// Implementation of dns.Wirer
func (d *PTR) Encode(b *dns.Wirebuf) {
	dns.DomainName(d.PTRDName).Encode(b)
}

// Implementation of dns.Wirer
func (d *PTR) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&d.PTRDName).Decode(b, pos, sniffer); err != nil {
		return
	}
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataPTR, d)
	}
	return
}

func (d *PTR) String() string {
	return d.PTRDName
}

type PX struct {
	// A 16 bit integer which specifies the preference given to
	// this RR among others at the same owner.  Lower values
	// are preferred.
	Preference uint16
	// A <domain-name> element containing <rfc822-domain>, the RFC822 part
	// of the MCGAM.
	MAP822 string
	// A <domain-name> element containing the value of
	// <x400-in-domain-syntax> derived from the X.400 part of the MCGAM.
	MAPX400 string
}

// Implementation of dns.Wirer
func (d *PX) Encode(b *dns.Wirebuf) {
	dns.Octets2(d.Preference).Encode(b)
	dns.DomainName(d.MAP822).Encode(b)
	dns.DomainName(d.MAPX400).Encode(b)
}

// Implementation of dns.Wirer
func (d *PX) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&d.Preference).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.DomainName)(&d.MAP822).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.DomainName)(&d.MAPX400).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataPX, d)
	}
	return
}

func (d *PX) String() string {
	return fmt.Sprintf("%d %s %s", d.Preference, d.MAP822, d.MAPX400)
}

// RDATA hodls DNS RR rdata for a unknown/unsupported RR type
type RDATA []byte

// Implementation of dns.Wirer
func (d *RDATA) Encode(b *dns.Wirebuf) {
	b.Buf = append(b.Buf, *d...)
}

// Implementation of dns.Wirer
func (d *RDATA) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	if *pos >= len(b) {
		*d = RDATA{}
		if sniffer != nil {
			sniffer(nil, nil, dns.SniffRData, d)
		}
		return
	}

	p0 := &b[*pos]
	n := len(b) - *pos
	*d = b[*pos:]
	*pos += n
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRData, d)
	}
	return
}

func (d *RDATA) String() string {
	return fmt.Sprintf("\\# %d %02x", len(*d), *d)
}

// RR holds a zone resource record data.
type RR struct {
	// An owner name, i.e., the name of the node to which this resource record pertains.
	Name string
	// Two octets containing one of the RR TYPE codes.
	Type
	// Two octets containing one of the RR CLASS codes.
	Class
	// A 32 bit signed integer that specifies the time interval
	// that the resource record may be cached before the source
	// of the information should again be consulted.  Zero
	// values are interpreted to mean that the RR can only be
	// used for the transaction in progress, and should not be
	// cached.  For example, SOA records are always distributed
	// with a zero TTL to prohibit caching.  Zero values can
	// also be used for extremely volatile data. 
	TTL int32
	//The format of this information varies according to the TYPE and CLASS of the resource record.
	RData dns.Wirer
}

func (rr *RR) String() string {
	switch rr.Type {
	default:
		return fmt.Sprintf("%s\t%s\t%d\t%s %s", rr.Name, rr.Class, rr.TTL, rr.Type, rr.RData)
	case TYPE_OPT:
		r := &EXT_RCODE{}
		r.FromTTL(rr.TTL)
		return fmt.Sprintf(
			"%s\t%d\t%s\t%s %s",
			rr.Name,
			uint16(rr.Class),
			r,
			rr.Type,
			rr.RData,
		)
	}
	panic("unreachable")
}

// Implementation of dns.Wirer
func (rr *RR) Encode(b *dns.Wirebuf) {
	dns.DomainName(rr.Name).Encode(b)
	rr.Type.Encode(b)
	rr.Class.Encode(b)
	dns.Octets4(rr.TTL).Encode(b)
	p0 := len(b.Buf)
	b.Buf = append(b.Buf, 0, 0)
	rr.RData.Encode(b)
	n := len(b.Buf) - (p0 + 2)
	b.Buf[p0] = byte(n >> 8)
	b.Buf[p0+1] = byte(n)
}

// Implementation of dns.Wirer
func (rr *RR) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&rr.Name).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octets2)(&rr.Type).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octets2)(&rr.Class).Decode(b, pos, sniffer); err != nil {
		return
	}

	var ttl dns.Octets4
	if err = ttl.Decode(b, pos, sniffer); err != nil {
		return
	}

	rr.TTL = int32(ttl)

	var rdlength dns.Octets2
	if err = rdlength.Decode(b, pos, sniffer); err != nil {
		return
	}

	switch rr.Type {
	case TYPE_A:
		rr.RData = &A{}
	case TYPE_AAAA:
		rr.RData = &AAAA{}
	case TYPE_AFSDB:
		rr.RData = &AFSDB{}
	case TYPE_CNAME:
		rr.RData = &CNAME{}
	case TYPE_DNAME:
		rr.RData = &DNAME{}
	case TYPE_DNSKEY:
		rr.RData = &DNSKEY{}
	case TYPE_DS:
		rr.RData = &DS{}
	case TYPE_GPOS:
		rr.RData = &GPOS{}
	case TYPE_HINFO:
		rr.RData = &HINFO{}
	case TYPE_ISDN:
		rr.RData = &ISDN{}
	case TYPE_KEY:
		rr.RData = &KEY{}
	case TYPE_LOC:
		rr.RData = &LOC{}
	case TYPE_MB:
		rr.RData = &MB{}
	case TYPE_MD:
		rr.RData = &MD{}
	case TYPE_MF:
		rr.RData = &MF{}
	case TYPE_MG:
		rr.RData = &MG{}
	case TYPE_MINFO:
		rr.RData = &MINFO{}
	case TYPE_MR:
		rr.RData = &MR{}
	case TYPE_MX:
		rr.RData = &MX{}
	case TYPE_NODATA:
		rr.RData = &NODATA{}
	case TYPE_NS:
		rr.RData = &NS{}
	case TYPE_NSAP:
		rr.RData = &NSAP{}
	case TYPE_NSAP_PTR:
		rr.RData = &NSAP_PTR{}
	case TYPE_NXDOMAIN:
		rr.RData = &NXDOMAIN{}
	case TYPE_NSEC3:
		rr.RData = &NSEC3{}
	case TYPE_NSEC3PARAM:
		rr.RData = &NSEC3PARAM{}
	case TYPE_NULL:
		rr.RData = &NULL{}
	case TYPE_OPT:
		rr.RData = &OPT{}
	case TYPE_PTR:
		rr.RData = &PTR{}
	case TYPE_PX:
		rr.RData = &PX{}
	case TYPE_RP:
		rr.RData = &RP{}
	case TYPE_RRSIG:
		rr.RData = &RRSIG{}
	case TYPE_RT:
		rr.RData = &RT{}
	case TYPE_SIG:
		rr.RData = &SIG{}
	case TYPE_SOA:
		rr.RData = &SOA{}
	case TYPE_TXT:
		rr.RData = &TXT{}
	case TYPE_WKS:
		rr.RData = &WKS{}
	case TYPE_X25:
		rr.RData = &X25{}
	default:
		rr.RData = &RDATA{}
	}

	if *pos+int(rdlength) > len(b) {
		return fmt.Errorf("malformed packet, len(RData) %d, len(buf) %d", rdlength, len(b)-*pos)
	}

	if err = rr.RData.Decode(b[:*pos+int(rdlength)], pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRR, rr)
	}
	return
}

// Equal compares a and b as per rfc2136/1.1
func (a *RR) Equal(b *RR) (equal bool) {
	//defer func() {
	//fmt.Printf("Equal(%q vs %q):%t\n", a, b, equal)
	//}()

	if a.Type != b.Type || a.Class != b.Class || strings.ToLower(a.Name) != strings.ToLower(b.Name) {
		return
	}

	// Name, Type, Class match
	switch x := a.RData.(type) {
	default:
		log.Fatalf("rr.RR.Equal() - internal error %T", x)
	case *RDATA:
		return bytes.Equal(*x, *b.RData.(*RDATA))
	case *A:
		return x.Address.String() == b.RData.(*A).Address.String()
	case *AAAA:
		return x.Address.String() == b.RData.(*AAAA).Address.String()
	case *AFSDB:
		y := b.RData.(*AFSDB)
		return x.SubType == y.SubType &&
			strings.ToLower(x.Hostname) == strings.ToLower(y.Hostname)
	case *CNAME:
		return strings.ToLower(x.Name) == strings.ToLower(b.RData.(*CNAME).Name)
	case *DNAME:
		return strings.ToLower(x.Name) == strings.ToLower(b.RData.(*DNAME).Name)
	case *DNSKEY:
		y := b.RData.(*DNSKEY)
		return x.Flags == y.Flags &&
			x.Protocol == y.Protocol &&
			x.Algorithm == y.Algorithm &&
			bytes.Equal(x.Key, y.Key)
	case *DS:
		y := b.RData.(*DS)
		return x.KeyTag == y.KeyTag &&
			x.AlgorithmType == y.AlgorithmType &&
			x.DigestType == y.DigestType &&
			bytes.Equal(x.Digest, y.Digest)
	case *GPOS:
		y := b.RData.(*GPOS)
		return x.Longitude == y.Longitude &&
			x.Latitude == y.Latitude &&
			x.Altitude == y.Altitude
	case *HINFO:
		y := b.RData.(*HINFO)
		return x.Cpu == y.Cpu && x.Os == y.Os
	case *ISDN:
		y := b.RData.(*ISDN)
		return x.ISDN == y.ISDN && x.Sa == y.Sa
	case *KEY:
		y := b.RData.(*KEY)
		return x.Flags == y.Flags &&
			x.Protocol == y.Protocol &&
			x.Algorithm == y.Algorithm &&
			bytes.Equal(x.Key, y.Key)
	case *LOC:
		y := b.RData.(*LOC)
		return x.Version == y.Version &&
			x.Size == y.Size &&
			x.HorizPre == y.HorizPre &&
			x.VertPre == y.VertPre &&
			x.Longitude == y.Longitude &&
			x.Latitude == y.Latitude &&
			x.Altitude == y.Altitude
	case *MB:
		y := b.RData.(*MB)
		return strings.ToLower(x.MADNAME) == strings.ToLower(y.MADNAME)
	case *MD:
		y := b.RData.(*MD)
		return strings.ToLower(x.MADNAME) == strings.ToLower(y.MADNAME)
	case *MF:
		y := b.RData.(*MF)
		return strings.ToLower(x.MADNAME) == strings.ToLower(y.MADNAME)
	case *MG:
		y := b.RData.(*MG)
		return strings.ToLower(x.MGNAME) == strings.ToLower(y.MGNAME)
	case *MINFO:
		y := b.RData.(*MINFO)
		return strings.ToLower(x.RMAILBX) == strings.ToLower(y.RMAILBX) &&
			strings.ToLower(x.EMAILBX) == strings.ToLower(y.EMAILBX)
	case *MR:
		y := b.RData.(*MR)
		return strings.ToLower(x.NEWNAME) == strings.ToLower(y.NEWNAME)
	case *MX:
		y := b.RData.(*MX)
		return x.Preference == y.Preference &&
			strings.ToLower(x.Exchange) == strings.ToLower(y.Exchange)
	case *NODATA:
		y := b.RData.(*NODATA)
		return x.Type == y.Type
	case *NXDOMAIN:
		return true
	case *NS:
		y := b.RData.(*NS)
		return strings.ToLower(x.NSDName) == strings.ToLower(y.NSDName)
	case *NSAP:
		return bytes.Compare(x.NSAP, b.RData.(*NSAP).NSAP) == 0
	case *NSAP_PTR:
		return strings.ToLower(x.Name) == strings.ToLower(b.RData.(*NSAP_PTR).Name)
	case *NSEC3:
		y := b.RData.(*NSEC3)
		return x.HashAlgorithm == y.HashAlgorithm &&
			x.Flags == y.Flags &&
			x.Iterations == y.Iterations &&
			bytes.Equal(x.Salt, y.Salt) &&
			bytes.Equal(x.NextHashedOwnerName, y.NextHashedOwnerName) &&
			bytes.Equal(x.TypeBitMaps, y.TypeBitMaps)
	case *NSEC3PARAM:
		y := b.RData.(*NSEC3PARAM)
		return x.HashAlgorithm == y.HashAlgorithm &&
			x.Flags == y.Flags &&
			x.Iterations == y.Iterations &&
			bytes.Equal(x.Salt, y.Salt)
	case *NULL:
		y := b.RData.(*NULL)
		return bytes.Equal(x.Data, y.Data)
	case *PTR:
		y := b.RData.(*PTR)
		return strings.ToLower(x.PTRDName) == strings.ToLower(y.PTRDName)
	case *PX:
		y := b.RData.(*PX)
		return x.Preference == y.Preference &&
			strings.ToLower(x.MAP822) == strings.ToLower(y.MAP822) &&
			strings.ToLower(x.MAPX400) == strings.ToLower(y.MAPX400)
	case *RP:
		y := b.RData.(*RP)
		return strings.ToLower(x.Mbox) == strings.ToLower(y.Mbox) &&
			strings.ToLower(x.Txt) == strings.ToLower(y.Txt)
	case *RRSIG:
		y := b.RData.(*RRSIG)
		return x.Type == y.Type &&
			x.AlgorithmType == y.AlgorithmType &&
			x.Labels == y.Labels &&
			x.TTL == y.TTL &&
			x.Expiration == y.Expiration &&
			x.KeyTag == y.KeyTag &&
			strings.ToLower(x.Name) == strings.ToLower(y.Name) &&
			bytes.Equal(x.Signature, y.Signature)
	case *RT:
		y := b.RData.(*RT)
		return x.Preference == y.Preference &&
			strings.ToLower(x.Hostname) == strings.ToLower(y.Hostname)
	case *SIG:
		y := b.RData.(*SIG)
		return x.Type == y.Type &&
			x.AlgorithmType == y.AlgorithmType &&
			x.Labels == y.Labels &&
			x.TTL == y.TTL &&
			x.Expiration == y.Expiration &&
			x.KeyTag == y.KeyTag &&
			strings.ToLower(x.Name) == strings.ToLower(y.Name) &&
			bytes.Equal(x.Signature, y.Signature)
	case *SOA:
		y := b.RData.(*SOA)
		return strings.ToLower(x.MName) == strings.ToLower(y.MName) &&
			strings.ToLower(x.RName) == strings.ToLower(y.RName) &&
			x.Serial == y.Serial &&
			x.Refresh == y.Refresh &&
			x.Retry == y.Retry &&
			x.Expire == y.Expire &&
			x.Minimum == y.Minimum
	case *TXT:
		return x.S == b.RData.(*TXT).S
	case *WKS:
		y := b.RData.(*WKS)
		if x.Protocol != y.Protocol ||
			len(x.Ports) != len(y.Ports) ||
			x.Address.String() != y.Address.String() {
			return false
		}
		for k := range x.Ports {
			if _, ok := y.Ports[k]; !ok {
				return false
			}
		}
		return true
	case *X25:
		return x.PSDN == b.RData.(*X25).PSDN
	}
	return
}

// RRs is a slice of resource records with attached convenience methods
type RRs []*RR

// Filter divides r to the wanted and other partitions.
func (r RRs) Filter(want func(r *RR) bool) (wanted, other RRs) {
	for _, r := range r {
		if want(r) {
			wanted = append(wanted, r)
		} else {
			other = append(other, r)
		}
	}
	return
}

func (r RRs) String() string {
	a := make([]string, len(r))
	for i, rec := range r {
		a[i] = rec.String()
	}
	return strings.Join(a, "\n")
}

// SetAdd computes a set union of r and rrs. Set membership predicate is RR.Equal,
// i.e. only resource records from rrs not comparing equal to any resource records
// in r are added/merged into the result set.
func (r *RRs) SetAdd(rrs RRs) {
	for _, newrec := range rrs {
		isnew := true
		for _, oldrec := range *r {
			if newrec.Equal(oldrec) {
				isnew = false
				break
			}
		}

		if isnew {
			*r = append(*r, newrec)
		}
	}
}

// Unique filters out any records from r which are Equal to any other record in r.
func (r *RRs) Unique() {
	y := RRs{}
	y.SetAdd(*r)
	*r = y
}

// Partition groups resource record of the same type.
// If unique == true then the result parts are processed by Unique.
func (r RRs) Partition(unique bool) (parts Parts) {
	parts = make(map[Type]RRs, len(r))
	for _, v := range r {
		parts[v.Type] = append(parts[v.Type], v)
	}
	if unique {
		for typ, part := range parts {
			part.Unique()
			parts[typ] = part
		}
	}
	return
}

// Pack packs r to Bytes
func (r RRs) Pack() (y Bytes) {
	y.Pack(r)
	return
}

// Parts is the type returned by Partition()
type Parts map[Type]RRs

// Join returns all parts of p.
func (p Parts) Join() (rrs RRs) {
	for _, part := range p {
		rrs = append(rrs, part...)
	}
	return
}

// SetAdd returns a set union of a and b. Set membership predicate is RR.Equal,
// i.e. only resource records from b not comparing equal to any resource records
// in a are added/merged into a.
func (a Parts) SetAdd(b Parts) {
	for newtyp, newrecs := range b {
		oldrecs, ok := a[newtyp]
		if !ok {
			a[newtyp] = newrecs
			continue
		}

		oldrecs.SetAdd(newrecs)
		a[newtyp] = oldrecs

	}
	return
}

// The Responsible Person RR can be associated with any node in the Domain Name
// System hierarchy, not just at the leaves of the tree.
type RP struct {
	// The first field, <mbox-dname>, is a domain name that specifies the
	// mailbox for the responsible person.  Its format in master files uses
	// the DNS convention for mailbox encoding, identical to that used for
	// the RNAME mailbox field in the SOA RR.  The root domain name (just
	// ".") may be specified for <mbox-dname> to indicate that no mailbox
	// is available.
	Mbox string
	// The second field, <txt-dname>, is a domain name for which TXT RR's
	// exist.  A subsequent query can be performed to retrieve the
	// associated TXT resource records at <txt-dname>.  This provides a
	// level of indirection so that the entity can be referred to from
	// multiple places in the DNS.  The root domain name (just ".") may be
	// specified for <txt-dname> to indicate that the TXT_DNAME is absent,
	// and no associated TXT RR exists.
	Txt string
}

// Implementation of dns.Wirer
func (d *RP) Encode(b *dns.Wirebuf) {
	(dns.DomainName)(d.Mbox).Encode(b)
	(dns.DomainName)(d.Txt).Encode(b)
}

// Implementation of dns.Wirer
func (d *RP) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&d.Mbox).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.DomainName)(&d.Txt).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataRP, d)
	}
	return
}

func (d *RP) String() string {
	return fmt.Sprintf("%s %s", d.Mbox, d.Txt)
}

// RRSIG holds the zone RRSIG RData (RFC4034)
type RRSIG struct {
	// The Type Covered field identifies the type of the RRset that is covered 
	// by this RRSIG record.
	Type
	//  The Algorithm Number field identifies the cryptographic algorithm used
	// to create the signature. 
	AlgorithmType
	// The Labels field specifies the number of labels in the original RRSIG RR owner name.
	Labels byte
	// The Original TTL field specifies the TTL of the covered RRset as it appears
	// in the authoritative zone.
	TTL int32
	// The Signature Expiration field specifies a validity period for the signature.
	// The RRSIG record MUST NOT be used for authentication after the expiration date.
	Expiration uint32
	// The Signature Inception field specifies a validity period for the signature.
	// The RRSIG record MUST NOT be used for authentication prior to the inception date.
	Inception uint32
	// The Key Tag field contains the key tag value of the DNSKEY RR that validates
	// this signature, in network byte order.
	KeyTag uint16
	// The Signer's Name field value identifies the owner name of the DNSKEY
	// RR that a validator is supposed to use to validate this signature.
	Name string
	// The Signature field contains the cryptographic signature that covers
	// the RRSIG RDATA (excluding the Signature field) and the RRset
	// specified by the RRSIG owner name, RRSIG class, and RRSIG Type
	// Covered field.
	Signature []byte
}

// Implementation of dns.Wirer
func (r *RRSIG) Encode(b *dns.Wirebuf) {
	dns.Octets2(r.Type).Encode(b)
	dns.Octet(r.AlgorithmType).Encode(b)
	dns.Octet(r.Labels).Encode(b)
	dns.Octets4(r.TTL).Encode(b)
	dns.Octets4(r.Expiration).Encode(b)
	dns.Octets4(r.Inception).Encode(b)
	dns.Octets2(r.KeyTag).Encode(b)
	b.DisableCompression()
	(*dns.DomainName)(&r.Name).Encode(b)
	b.EnableCompression()
	b.Buf = append(b.Buf, r.Signature...)
}

// Implementation of dns.Wirer
func (r *RRSIG) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&r.Type).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octet)(&r.AlgorithmType).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octet)(&r.Labels).Decode(b, pos, sniffer); err != nil {
		return
	}

	var ttl dns.Octets4
	if err = ttl.Decode(b, pos, sniffer); err != nil {
		return
	}

	r.TTL = int32(ttl)

	if err = (*dns.Octets4)(&r.Expiration).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octets4)(&r.Inception).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octets2)(&r.KeyTag).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.DomainName)(&r.Name).Decode(b, pos, sniffer); err != nil {
		return
	}

	n := len(b) - *pos
	if n <= 0 {
		return fmt.Errorf("(*RRSIG).Decode: no signature data")
	}

	r.Signature = make([]byte, n)
	copy(r.Signature, b[*pos:])
	*pos += n
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataRRSIG, r)
	}
	return
}

func (r *RRSIG) String() string {
	return fmt.Sprintf("%s %d %d %d %s %s %d %s %s",
		r.Type,
		r.AlgorithmType,
		r.Labels,
		r.TTL,
		dns.Seconds2String(int64(r.Expiration)),
		dns.Seconds2String(int64(r.Inception)),
		r.KeyTag,
		r.Name,
		strutil.Base64Encode(r.Signature),
	)
}

// The RT resource record provides a route-through binding for hosts that do
// not have their own direct wide area network addresses.  It is used in much
// the same way as the MX RR.
//
// Both RDATA fields are required in all RT RRs.
type RT struct {
	// The first field, <preference>, is a 16 bit integer, representing the
	// preference of the route.  Smaller numbers indicate more preferred
	// routes.
	Preference uint16
	// <intermediate-host> is the domain name of a host which will serve as
	// an intermediate in reaching the host specified by <owner>.  The DNS
	// RRs associated with <intermediate-host> are expected to include at
	// least one A, X25, or ISDN record.
	Hostname string
}

// Implementation of dns.Wirer
func (d *RT) Encode(b *dns.Wirebuf) {
	(dns.Octets2)(d.Preference).Encode(b)
	(dns.DomainName)(d.Hostname).Encode(b)
}

// Implementation of dns.Wirer
func (d *RT) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&d.Preference).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.DomainName)(&d.Hostname).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataRT, d)
	}
	return
}

func (d *RT) String() string {
	return fmt.Sprintf("%d %s", d.Preference, d.Hostname)
}

// The SIG or "signature" resource record (RR) is the fundamental way that data
// is authenticated in the secure Domain Name System (DNS). As such it is the
// heart of the security provided.
type SIG struct {
	// The Type Covered field identifies the type of the RRset that is covered 
	// by this SIG record.
	Type
	//  The Algorithm Number field identifies the cryptographic algorithm used
	// to create the signature. 
	AlgorithmType
	// The Labels field specifies the number of labels in the original SIG RR owner name.
	Labels byte
	// The Original TTL field specifies the TTL of the covered RRset as it appears
	// in the authoritative zone.
	TTL int32
	// The Signature Expiration field specifies a validity period for the signature.
	// The SIG record MUST NOT be used for authentication after the expiration date.
	Expiration uint32
	// The Signature Inception field specifies a validity period for the signature.
	// The SIG record MUST NOT be used for authentication prior to the inception date.
	Inception uint32
	// The Key Tag field contains the key tag value of the DNSKEY RR that validates
	// this signature, in network byte order.
	KeyTag uint16
	// The Signer's Name field value identifies the owner name of the DNSKEY
	// RR that a validator is supposed to use to validate this signature.
	Name string
	// The Signature field contains the cryptographic signature that covers
	// the SIG RDATA (excluding the Signature field) and the RRset
	// specified by the SIG owner name, SIG class, and SIG Type
	// Covered field.
	Signature []byte
}

// Implementation of dns.Wirer
func (r *SIG) Encode(b *dns.Wirebuf) {
	dns.Octets2(r.Type).Encode(b)
	dns.Octet(r.AlgorithmType).Encode(b)
	dns.Octet(r.Labels).Encode(b)
	dns.Octets4(r.TTL).Encode(b)
	dns.Octets4(r.Expiration).Encode(b)
	dns.Octets4(r.Inception).Encode(b)
	dns.Octets2(r.KeyTag).Encode(b)
	b.DisableCompression()
	(*dns.DomainName)(&r.Name).Encode(b)
	b.EnableCompression()
	b.Buf = append(b.Buf, r.Signature...)
}

// Implementation of dns.Wirer
func (r *SIG) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&r.Type).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octet)(&r.AlgorithmType).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octet)(&r.Labels).Decode(b, pos, sniffer); err != nil {
		return
	}

	var ttl dns.Octets4
	if err = ttl.Decode(b, pos, sniffer); err != nil {
		return
	}

	r.TTL = int32(ttl)

	if err = (*dns.Octets4)(&r.Expiration).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octets4)(&r.Inception).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octets2)(&r.KeyTag).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.DomainName)(&r.Name).Decode(b, pos, sniffer); err != nil {
		return
	}

	n := len(b) - *pos
	if n <= 0 {
		return fmt.Errorf("(*SIG).Decode: no signature data")
	}

	r.Signature = make([]byte, n)
	copy(r.Signature, b[*pos:])
	*pos += n
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataSIG, r)
	}
	return
}

func (r *SIG) String() string {
	return fmt.Sprintf("%s %d %d %d %s %s %d %s %s",
		r.Type,
		r.AlgorithmType,
		r.Labels,
		r.TTL,
		dns.Seconds2String(int64(r.Expiration)),
		dns.Seconds2String(int64(r.Inception)),
		r.KeyTag,
		r.Name,
		strutil.Base64Encode(r.Signature),
	)
}

// SOA holds the zone SOA RData
type SOA struct {
	// The <domain-name> of the name server that was the
	// original or primary source of data for this zone.
	MName string
	// A <domain-name> which specifies the mailbox of the
	// person responsible for this zone.
	RName string
	// The unsigned 32 bit version number of the original copy
	// of the zone.  Zone transfers preserve this value.  This
	// value wraps and should be compared using sequence space
	// arithmetic.
	Serial uint32
	// A 32 bit time interval before the zone should be
	// refreshed.
	Refresh uint32
	// A 32 bit time interval that should elapse before a
	// failed refresh should be retried.
	Retry uint32
	// A 32 bit time value that specifies the upper limit on
	// the time interval that can elapse before the zone is no
	// longer authoritative.
	Expire uint32
	// The unsigned 32 bit minimum TTL field that should be
	// exported with any RR from this zone.
	Minimum uint32
}

// Implementation of dns.Wirer
func (d *SOA) Encode(b *dns.Wirebuf) {
	dns.DomainName(d.MName).Encode(b)
	dns.DomainName(d.RName).Encode(b)
	dns.Octets4(d.Serial).Encode(b)
	dns.Octets4(d.Refresh).Encode(b)
	dns.Octets4(d.Retry).Encode(b)
	dns.Octets4(d.Expire).Encode(b)
	dns.Octets4(d.Minimum).Encode(b)
}

// Implementation of dns.Wirer
func (d *SOA) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&d.MName).Decode(b, pos, sniffer); err != nil {
		return
	}
	if err = (*dns.DomainName)(&d.RName).Decode(b, pos, sniffer); err != nil {
		return
	}
	if (*dns.Octets4)(&d.Serial).Decode(b, pos, sniffer); err != nil {
		return
	}
	if (*dns.Octets4)(&d.Refresh).Decode(b, pos, sniffer); err != nil {
		return
	}
	if (*dns.Octets4)(&d.Retry).Decode(b, pos, sniffer); err != nil {
		return
	}
	if (*dns.Octets4)(&d.Expire).Decode(b, pos, sniffer); err != nil {
		return
	}
	if err = (*dns.Octets4)(&d.Minimum).Decode(b, pos, sniffer); err != nil {
		return
	}
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataSOA, d)
	}
	return
}

func (d *SOA) String() string {
	return fmt.Sprintf("%s %s %d %d %d %d %d", d.MName, d.RName, d.Serial, d.Refresh, d.Retry, d.Expire, d.Minimum)
}

// TXT holds the TXT RData
type TXT struct {
	S string
}

// Implementation of dns.Wirer
func (t *TXT) Encode(b *dns.Wirebuf) {
	dns.CharString(t.S).Encode(b)
}

// Implementation of dns.Wirer
func (t *TXT) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	s := ""
	for *pos < len(b) {
		var part dns.CharString
		if err = part.Decode(b, pos, sniffer); err != nil {
			return
		}

		s += string(part)
	}
	t.S = s
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataTXT, t)
	}
	return
}

func (t *TXT) String() string {
	return fmt.Sprintf(`"%s"`, strings.Replace(t.S, `"`, `\"`, -1))
}

// The WKS record is used to describe the well known services supported by
// a particular protocol on a particular internet address.  The PROTOCOL
// field specifies an IP protocol number, and the bit map has one bit per
// port of the specified protocol.  The first bit corresponds to port 0,
// the second to port 1, etc.  If the bit map does not include a bit for a
// protocol of interest, that bit is assumed zero.  The appropriate values
// and mnemonics for ports and protocols are specified in [RFC-1010].
//
// For example, if PROTOCOL=TCP (6), the 26th bit corresponds to TCP port
// 25 (SMTP).  If this bit is set, a SMTP server should be listening on TCP
// port 25; if zero, SMTP service is not supported on the specified
// address.
//
// The purpose of WKS RRs is to provide availability information for
// servers for TCP and UDP.  If a server supports both TCP and UDP, or has
// multiple Internet addresses, then multiple WKS RRs are used.
//
// WKS RRs cause no additional section processing.
//
// In master files, both ports and protocols are expressed using mnemonics
// or decimal numbers.
type WKS struct {
	Address  net.IP
	Protocol IP_Protocol
	Ports    map[IP_Port]struct{}
}

// Implementation of dns.Wirer
func (d *WKS) Encode(b *dns.Wirebuf) {
	ip4(d.Address).Encode(b)
	dns.Octet(d.Protocol).Encode(b)
	bits := make([]byte, 0, 1024/8)
	for k := range d.Ports {
		i := int(k)
		x := i >> 3
		mask := 1 << uint(i&7)
		if x >= len(bits) {
			bits = bits[:x+1]
		}
		bits[x] |= byte(mask)
	}
	b.Buf = append(b.Buf, bits...)
}

// Implementation of dns.Wirer
func (d *WKS) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*ip4)(&d.Address).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octet)(&d.Protocol).Decode(b, pos, sniffer); err != nil {
		return
	}

	d.Ports = map[IP_Port]struct{}{}
	n := len(b) - *pos
	if n == 0 {
		if sniffer != nil {
			sniffer(p0, &b[*pos-1], dns.SniffRDataWKS, d)
		}
		return
	}

	b = b[*pos:]
	for i, v := range b {
		for bit := 0; v != 0; bit, v = bit+1, v>>1 {
			if v&1 != 0 {
				d.Ports[IP_Port(i<<3+bit)] = struct{}{}
			}
		}
	}
	*pos += n
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataWKS, d)
	}
	return
}

func (d *WKS) String() string {
	buf := &bytes.Buffer{}
	buf.WriteString(d.Address.String())
	buf.WriteString(" ")
	proto := IP_Protocols[d.Protocol]
	if proto == "" {
		proto = strconv.Itoa(int(d.Protocol))
	}
	buf.WriteString(proto)
	for k := range d.Ports {
		port := IP_Ports[k]
		if port == "" {
			port = strconv.Itoa(int(k))
		}
		buf.WriteString(" ")
		buf.WriteString(port)
	}
	return buf.String()
}

// TYPE fields are used in resource records.  Note that these types are a
// subset of msg.QTYPEs.
type Type uint16

// Type codes
const (
	_ Type = iota

	TYPE_A          //  1 a host address                              [RFC1035]
	TYPE_NS         //  2 an authoritative name server                [RFC1035]
	TYPE_MD         //  3 a mail destination (Obsolete - use MX)      [RFC1035]
	TYPE_MF         //  4 a mail forwarder (Obsolete - use MX)        [RFC1035]
	TYPE_CNAME      //  5 the canonical name for an alias             [RFC1035]
	TYPE_SOA        //  6 marks the start of a zone of authority      [RFC1035]
	TYPE_MB         //  7 a mailbox domain name (EXPERIMENTAL)        [RFC1035]
	TYPE_MG         //  8 a mail group member (EXPERIMENTAL)          [RFC1035]
	TYPE_MR         //  9 a mail rename domain name (EXPERIMENTAL     [RFC1035]
	TYPE_NULL       // 10 a null RR (EXPERIMENTAL)                    [RFC1035]
	TYPE_WKS        // 11 a well known service description            [RFC1035]
	TYPE_PTR        // 12 a domain name pointer                       [RFC1035]
	TYPE_HINFO      // 13 host information                            [RFC1035]
	TYPE_MINFO      // 14 mailbox or mail list information            [RFC1035]
	TYPE_MX         // 15 mail exchange                               [RFC1035]
	TYPE_TXT        // 16 text strings                                [RFC1035]
	TYPE_RP         // 17 for Responsible Person                      [RFC1183]
	TYPE_AFSDB      // 18 for AFS Data Base location                  [RFC1183][RFC5864]
	TYPE_X25        // 19 for X.25 PSDN address                       [RFC1183]
	TYPE_ISDN       // 20 for ISDN address                            [RFC1183]
	TYPE_RT         // 21 for Route Through                           [RFC1183]
	TYPE_NSAP       // 22 for NSAP address, NSAP style A record       [RFC1706]
	TYPE_NSAP_PTR   // 23 for domain name pointer, NSAP style         [RFC1348]
	TYPE_SIG        // 24 for security signature                      [RFC4034][RFC3755][RFC2535]
	TYPE_KEY        // 25 for security key                            [RFC4034][RFC3755][RFC2535]
	TYPE_PX         // 26 X.400 mail mapping information              [RFC2163]
	TYPE_GPOS       // 27 Geographical Position                       [RFC1712]
	TYPE_AAAA       // 28 IP6 Address                                 [RFC3596]
	TYPE_LOC        // 29 Location Information                        [RFC1876]
	TYPE_NXT        // 30 Next Domain - OBSOLETE                      [RFC3755][RFC2535]
	TYPE_EID        // 31 Endpoint Identifier                         [Patton]
	TYPE_NIMLOC     // 32 Nimrod Locator                              [Patton]
	TYPE_SRV        // 33 Server Selection                            [RFC2782]
	TYPE_ATMA       // 34 ATM Address                                 [ATMDOC]
	TYPE_NAPTR      // 35 Naming Authority Pointer                    [RFC2915][RFC2168][RFC3403]
	TYPE_KX         // 36 Key Exchanger                               [RFC2230]
	TYPE_CERT       // 37 CERT                                        [RFC4398]
	TYPE_A6         // 38 A6 (Experimental)                           [RFC3226][RFC2874]
	TYPE_DNAME      // 39 DNAME                                       [RFC2672]
	TYPE_SINK       // 40 SINK                                        [Eastlake]
	TYPE_OPT        // 41 OPT                                         [RFC2671]
	TYPE_APL        // 42 APL                                         [RFC3123]
	TYPE_DS         // 43 Delegation Signer                           [RFC4034][RFC3658]
	TYPE_SSHFP      // 44 SSH Key Fingerprint                         [RFC4255]
	TYPE_IPSECKEY   // 45 IPSECKEY                                    [RFC4025]
	TYPE_RRSIG      // 46 RRSIG                                       [RFC4034][RFC3755]
	TYPE_NSEC       // 47 NSEC                                        [RFC4034][RFC3755]
	TYPE_DNSKEY     // 48 DNSKEY                                      [RFC4034][RFC3755]
	TYPE_DHCID      // 49 DHCID                                       [RFC4701]
	TYPE_NSEC3      // 50 NSEC3                                       [RFC5155]
	TYPE_NSEC3PARAM // 51 NSEC3PARAM                                  [RFC5155]
)

const (
	_ Type = iota + 54

	TYPE_HIP    // 55 Host Identity Protocol                      [RFC5205]
	TYPE_NINFO  // 56 NINFO                                       [Reid]
	TYPE_RKEY   // 57 RKEY                                        [Reid]
	TYPE_TALINK // 58 Trust Anchor LINK                           [Wijngaards]
	TYPE_CDS    // 59 Child DS                                    [Barwood]
)

const (
	_ Type = iota + 98

	TYPE_SPF    //  99                                             [RFC4408]
	TYPE_UINFO  // 100                                             [IANA-Reserved]
	TYPE_UID    // 101                                             [IANA-Reserved]
	TYPE_GID    // 102                                             [IANA-Reserved]
	TYPE_UNSPEC // 103                                             [IANA-Reserved]
)

const (
	_ Type = iota + 248

	TYPE_TKEY  // 249 Transaction Key                            [RFC2930]
	TYPE_TSIG  // 250 Transaction Signature                      [RFC2845]
	TYPE_IXFR  // 251 incremental transfer                       [RFC1995]
	TYPE_AXFR  // 252 transfer of an entire zone                 [RFC1035][RFC5936]
	TYPE_MAILB // 253 mailbox-related RRs (MB, MG or MR)         [RFC1035]
	TYPE_MAILA // 254 mail agent RRs (Obsolete - see MX)         [RFC1035]
)

const (
	_ Type = iota + 255

	TYPE_URI // 256 URI                                        [Faltstrom]
	TYPE_CAA // 257 Certification Authority Authorization      [Hallam-Baker]
)

const (
	_ Type = iota + 0x7FFF

	TYPE_TA  // 32768   DNSSEC Trust Authorities               [Weiler]           2005-12-13
	TYPE_DLV // 32769   DNSSEC Lookaside Validation            [RFC4431]
)

const (
	_ Type = iota + 0xFEFF

	TYPE_NODATA //      Pseudo types in the "reserved for private use" area
	TYPE_NXDOMAIN
)

var Types = map[Type]string{
	TYPE_A6:         "A6",
	TYPE_A:          "A",
	TYPE_AAAA:       "AAAA",
	TYPE_AFSDB:      "AFSDB",
	TYPE_APL:        "APL",
	TYPE_ATMA:       "ATMA",
	TYPE_AXFR:       "AXFR",
	TYPE_CAA:        "CAA",
	TYPE_CDS:        "CDS",
	TYPE_CERT:       "CERT",
	TYPE_CNAME:      "CNAME",
	TYPE_DHCID:      "DHCID",
	TYPE_DLV:        "DLV",
	TYPE_DNAME:      "DNAME",
	TYPE_DNSKEY:     "DNSKEY",
	TYPE_DS:         "DS",
	TYPE_EID:        "EID",
	TYPE_GID:        "GID",
	TYPE_GPOS:       "GPOS",
	TYPE_HINFO:      "HINFO",
	TYPE_HIP:        "HIP",
	TYPE_IPSECKEY:   "IPSECKEY",
	TYPE_ISDN:       "ISDN",
	TYPE_IXFR:       "IXFR",
	TYPE_KEY:        "KEY",
	TYPE_KX:         "KX",
	TYPE_LOC:        "LOC",
	TYPE_MAILA:      "MAILA",
	TYPE_MAILB:      "MAILB",
	TYPE_MB:         "MB",
	TYPE_MD:         "MD",
	TYPE_MF:         "MF",
	TYPE_MG:         "MG",
	TYPE_MINFO:      "MINFO",
	TYPE_MR:         "MR",
	TYPE_MX:         "MX",
	TYPE_NAPTR:      "NAPTR",
	TYPE_NIMLOC:     "NIMLOC",
	TYPE_NINFO:      "NINFO",
	TYPE_NODATA:     "NODATA",
	TYPE_NS:         "NS",
	TYPE_NSAP:       "NSAP",
	TYPE_NSAP_PTR:   "NSAP-PTR",
	TYPE_NSEC3:      "NSEC3",
	TYPE_NSEC3PARAM: "NSEC3PARAM",
	TYPE_NSEC:       "NSEC",
	TYPE_NULL:       "NULL",
	TYPE_NXDOMAIN:   "NXDOMAIN",
	TYPE_NXT:        "NXT",
	TYPE_OPT:        "OPT",
	TYPE_PTR:        "PTR",
	TYPE_PX:         "PX",
	TYPE_RKEY:       "RKEY",
	TYPE_RP:         "RP",
	TYPE_RRSIG:      "RRSIG",
	TYPE_RT:         "RT",
	TYPE_SIG:        "SIG",
	TYPE_SINK:       "SINK",
	TYPE_SOA:        "SOA",
	TYPE_SPF:        "SPF",
	TYPE_SRV:        "SRV",
	TYPE_SSHFP:      "SSHFP",
	TYPE_TA:         "TA",
	TYPE_TALINK:     "TALINK",
	TYPE_TKEY:       "TKEY",
	TYPE_TSIG:       "TSIG",
	TYPE_TXT:        "TXT",
	TYPE_UID:        "UID",
	TYPE_UINFO:      "UINFO",
	TYPE_UNSPEC:     "UNSPEC",
	TYPE_URI:        "URI",
	TYPE_WKS:        "WKS",
	TYPE_X25:        "X25",
}

func (n Type) String() (s string) {
	var ok bool
	if s, ok = Types[n]; !ok {
		return fmt.Sprintf("TYPE%d", uint16(n))
	}
	return
}

// Implementation of dns.Wirer
func (n Type) Encode(b *dns.Wirebuf) {
	dns.Octets2(n).Encode(b)
}

// Implementation of dns.Wirer
func (n *Type) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(n).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffType, *n)
	}
	return
}

// X25 RData
type X25 struct {
	// <PSDN-address> is required in all X25 RRs.
	//
	// <PSDN-address> identifies the PSDN (Public Switched Data Network)
	// address in the X.121 [10] numbering plan associated with <owner>.
	// Its format in master files is a <character-string> syntactically
	// identical to that used in TXT and HINFO.
	PSDN string
}

// Implementation of dns.Wirer
func (d *X25) Encode(b *dns.Wirebuf) {
	(dns.CharString)(d.PSDN).Encode(b)
}

// Implementation of dns.Wirer
func (d *X25) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.CharString)(&d.PSDN).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataX25, d)
	}
	return
}

func (d *X25) String() string {
	return fmt.Sprintf(`"%s"`, strings.Replace(d.PSDN, `"`, `\"`, -1))
}
