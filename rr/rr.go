// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

/*
IANA checklist: http://www.iana.org/assignments/dns-parameters (last updated 2012-01-31)

Registry:
TYPE         Value and meaning                              Reference
-----------  ---------------------------------------------  ---------
//A            1 a host address                               [RFC1035] done
//NS           2 an authoritative name server                 [RFC1035] done
//MD           3 a mail destination (OBSOLETE - use MX)       [RFC1035] done
//MF           4 a mail forwarder (OBSOLETE - use MX)         [RFC1035] done
//CNAME        5 the canonical name for an alias              [RFC1035] done
//SOA          6 marks the start of a zone of authority       [RFC1035] done
//MB           7 a mailbox domain name (EXPERIMENTAL)         [RFC1035] done
//MG           8 a mail group member (EXPERIMENTAL)           [RFC1035] done
//MR           9 a mail rename domain name (EXPERIMENTAL)     [RFC1035] done
//NULL         10 a null RR (EXPERIMENTAL)                    [RFC1035] done
//WKS          11 a well known service description            [RFC1035] done
//PTR          12 a domain name pointer                       [RFC1035] done
//HINFO        13 host information                            [RFC1035] done
//MINFO        14 mailbox or mail list information            [RFC1035] done
//MX           15 mail exchange                               [RFC1035] done
//TXT          16 text strings                                [RFC1035] done
//RP           17 for Responsible Person                      [RFC1183] done
//AFSDB        18 for AFS Data Base location                  [RFC1183][RFC5864] done
//X25          19 for X.25 PSDN address                       [RFC1183] done
//ISDN         20 for ISDN address                            [RFC1183] done
//RT           21 for Route Through                           [RFC1183] done
//NSAP         22 for NSAP address, NSAP style A record       [RFC1706] done
//NSAP-PTR     23 for domain name pointer, NSAP style         [RFC1348][RFC1637][RFC1706] done
//SIG          24 for security signature                      [RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2931][RFC3110][RFC3008] done
//KEY          25 for security key                            [RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2539][RFC3008][RFC3110] done
//PX           26 X.400 mail mapping information              [RFC2163] done
//GPOS         27 Geographical Position                       [RFC1712] done
//AAAA         28 IP6 Address                                 [RFC3596] done
//LOC          29 Location Information                        [RFC1876] done
NXT          30 Next Domain (OBSOLETE)                      [RFC3755][RFC2535]
EID          31 Endpoint Identifier                         [Patton][Patton1995]
NIMLOC       32 Nimrod Locator                              [Patton][Patton1995]
//SRV          33 Server Selection                            [RFC2782] done
ATMA         34 ATM Address                                 [ATMDOC]
//NAPTR        35 Naming Authority Pointer                    [RFC2915][RFC2168][RFC3403] done
//KX           36 Key Exchanger                               [RFC2230] done
//CERT         37 CERT                                        [RFC4398] done
A6           38 A6 (OBSOLETE - use AAAA)                    [RFC3226][RFC2874][RFC-jiang-a6-to-historic-00.txt]
//DNAME        39 DNAME                                       [RFC2672] done
SINK         40 SINK                                        [Eastlake][Eastlake2002]
//OPT          41 OPT                                         [RFC2671][RFC3225] done
APL          42 APL                                         [RFC3123]
//DS           43 Delegation Signer                           [RFC4034][RFC3658] done
//SSHFP        44 SSH Key Fingerprint                         [RFC4255] done
//IPSECKEY     45 IPSECKEY                                    [RFC4025] done
//RRSIG        46 RRSIG                                       [RFC4034][RFC3755] done
//NSEC         47 NSEC                                        [RFC4034][RFC3755] done
//DNSKEY       48 DNSKEY                                      [RFC4034][RFC3755] done
//DHCID        49 DHCID                                       [RFC4701] done
//NSEC3        50 NSEC3                                       [RFC5155] done
//NSEC3PARAM   51 NSEC3PARAM                                  [RFC5155] done
Unassigned   52-54
//HIP          55 Host Identity Protocol                      [RFC5205] done
NINFO        56 NINFO                                       [Reid]
RKEY         57 RKEY                                        [Reid]
//TALINK       58 Trust Anchor LINK                           [Wijngaards] done
CDS          59 Child DS                                    [Barwood]
Unassigned   60-98
//SPF          99                                             [RFC4408] done
UINFO        100                                            [IANA-Reserved]
UID          101                                            [IANA-Reserved]
GID          102                                            [IANA-Reserved]
UNSPEC       103                                            [IANA-Reserved]
Unassigned   104-248
//TKEY         249 Transaction Key                            [RFC2930] only a QTYPE, done
//TSIG         250 Transaction Signature                      [RFC2845] only a QTYPE, done
//IXFR         251 incremental transfer                       [RFC1995] only a QTYPE, done
//AXFR         252 transfer of an entire zone                 [RFC1035][RFC5936] only a QTYPE, done
//MAILB        253 mailbox-related RRs (MB, MG or MR)         [RFC1035] only a QTYPE, done
//MAILA        254 mail agent RRs (OBSOLETE - see MX)         [RFC1035] only a QTYPE, done
//*            255 A request for all records                  [RFC1035] only a QTYPE, done
URI          256 URI                                        [Faltstrom]
//CAA          257 Certification Authority Authorization      [Hallam-Baker]
Unassigned   258-32767
//TA           32768   DNSSEC Trust Authorities               [Weiler] done
//DLV          32769   DNSSEC Lookaside Validation            [RFC4431] done
Unassigned   32770-65279  
Private use  65280-65534
Reserved     65535 

Note: In [RFC1002], two types are defined.  It is not clear that these
are in use, though if so their assignment does conflict with those above.
	NB	32	NetBIOS general Name Service
	NBSTAT	33	NetBIOS NODE STATUS

*/

/*

-- Types to do:
+check ALL "*"

---- Supported RR types "diff" vs Miek G.'s dns lib @ https://github.com/miekg/dns

+AFSDB
+GPOS
+ISDN
+KEY
+MD
+MF
+NSAP
+NSAP-PTR
+NULL
+PX
+RP
+RT
+SIG
+X25

-TLSA (RFC? DANE WG?)
-URI (RFC4501)

=A
=AAAA
=CERT
=CNAME
=DHCID
=DLV
=DNAME
=DNSKEY
=DS
=HINFO
=HIP
=IPSECKEY
=KX
=LOC
=MB
=MG
=MINFO
=MR
=MX
=NAPTR
=NS
=NSEC
=NSEC3
=NSEC3PARAM
=PTR
=RRSIG
=SOA
=SPF
=SRV
=SSHFP
=TA
=TALINK
=TKEY
=TSIG
=TXT
=WKS
=any/unknown (RFC3597)

*/

// Package rr supports DNS resource records (RFC 1035 chapter 3.2).
package rr

import (
	"bytes"
	"crypto"
	_ "crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/cznic/dns"
	"github.com/cznic/strutil"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

const asserts = false

var sha256 = crypto.SHA256

func init() {
	if asserts {
		println("WARNING: cznic/dns/rr - assertions enabled")
	}
}

func quote(s string) string {
	return dns.CharString(s).Quoted()
}

// A holds the zone A RData
type A struct {
	Address net.IP // A 32 bit Internet address.
}

// Implementation of dns.Wirer
func (rd *A) Encode(b *dns.Wirebuf) {
	ip4(rd.Address).Encode(b)
}

// Implementation of dns.Wirer
func (rd *A) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*ip4)(&rd.Address).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataA, rd)
	}
	return
}

func (rd *A) String() string {
	return rd.Address.String()
}

// AAAA holds the zone AAAA RData
type AAAA struct {
	Address net.IP // A 128 bit Internet address.
}

// Implementation of dns.Wirer
func (rd *AAAA) Encode(b *dns.Wirebuf) {
	ip6(rd.Address).Encode(b)
}

// Implementation of dns.Wirer
func (rd *AAAA) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*ip6)(&rd.Address).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataAAAA, rd)
	}
	return
}

func (rd *AAAA) String() string {
	return rd.Address.String()
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
func (rd *AFSDB) Encode(b *dns.Wirebuf) {
	(dns.Octets2)(rd.SubType).Encode(b)
	(dns.DomainName)(rd.Hostname).Encode(b)
}

// Implementation of dns.Wirer
func (rd *AFSDB) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&rd.SubType).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.DomainName)(&rd.Hostname).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataAFSDB, rd)
	}
	return
}

func (rd *AFSDB) String() string {
	return fmt.Sprintf("%d %s", rd.SubType, rd.Hostname)
}

// CertType is the type of the Type field in the CERT RData
type CertType uint16

// Values of CertifiacteType as defined in rfc4398.
//
//  2.1.  Certificate Type Values
//
//   The following values are defined or reserved:
//
//         Value  Mnemonic  Certificate Type
//         -----  --------  ----------------
//             0            Reserved
//             1  PKIX      X.509 as per PKIX
//             2  SPKI      SPKI certificate
//             3  PGP       OpenPGP packet
//             4  IPKIX     The URL of an X.509 data object
//             5  ISPKI     The URL of an SPKI certificate
//             6  IPGP      The fingerprint and URL of an OpenPGP packet
//             7  ACPKIX    Attribute Certificate
//             8  IACPKIX   The URL of an Attribute Certificate
//         9-252            Available for IANA assignment
//           253  URI       URI private
//           254  OID       OID private
//           255            Reserved
//     256-65279            Available for IANA assignment
//   65280-65534            Experimental
//         65535            Reserved
const (
	CertReserved0 CertType = iota
	CertPKIX
	CertSPKI
	CertPGP
	CertIPKIX
	CertIPGP
	CertACPKIX
	CertIACPKIX
	CertURI = iota + 244
	CertOID
	CertReserved255
	CertExperimental65280 = 65280
	CertExperimental65534 = 65534
	CertReserved          = 65535
)

type CERT struct {
	// The type field is the certificate type as defined by CertType.
	Type CertType
	// The key tag field is the 16-bit value computed for the key embedded
	// in the certificate, using the RRSIG Key Tag algorithm described in
	// Appendix B of [12].  This field is used as an efficiency measure to
	// pick which CERT RRs may be applicable to a particular key.  The key
	// tag can be calculated for the key in question, and then only CERT RRs
	// with the same key tag need to be examined.  Note that two different
	// keys can have the same key tag.  However, the key MUST be transformed
	// to the format it would have as the public key portion of a DNSKEY RR
	// before the key tag is computed.  This is only possible if the key is
	// applicable to an algorithm and complies to limits (such as key size)
	// defined for DNS security.  If it is not, the algorithm field MUST be
	// zero and the tag field is meaningless and SHOULD be zero.
	KeyTag uint16
	// The algorithm field has the same meaning as the algorithm field in
	// DNSKEY and RRSIG RRs [12], except that a zero algorithm field
	// indicates that the algorithm is unknown to a secure DNS, which may
	// simply be the result of the algorithm not having been standardized
	// for DNSSEC [11].
	//
	// Defined by AlgorithmType
	Algorithm AlgorithmType
	// Certificate or CRL
	Cert []byte
}

// Implementation of dns.Wirer
func (rd *CERT) Encode(b *dns.Wirebuf) {
	dns.Octets2(rd.Type).Encode(b)
	dns.Octets2(rd.KeyTag).Encode(b)
	dns.Octet(rd.Algorithm).Encode(b)
	b.Buf = append(b.Buf, rd.Cert...)
}

// Implementation of dns.Wirer
func (rd *CERT) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&rd.Type).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octets2)(&rd.KeyTag).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octet)(&rd.Algorithm).Decode(b, pos, sniffer); err != nil {
		return
	}

	n := len(b) - *pos
	if n <= 0 {
		return fmt.Errorf("(*CERT).Decode: no certificate data")
	}

	rd.Cert = make([]byte, n)
	copy(rd.Cert, b[*pos:])
	*pos += n
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataCERT, rd)
	}
	return
}

func (rd *CERT) String() string {
	return fmt.Sprintf("%d %d %d %s",
		rd.Type,
		rd.KeyTag,
		rd.Algorithm,
		strutil.Base64Encode(rd.Cert),
	)
}

// CNAME holds the zone CNAME RData
type CNAME struct {
	Name string
}

// Implementation of dns.Wirer
func (rd CNAME) Encode(b *dns.Wirebuf) {
	(dns.DomainName)(rd.Name).Encode(b)
}

// Implementation of dns.Wirer
func (rd *CNAME) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&rd.Name).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataCNAME, rd)
	}
	return
}

func (rd CNAME) String() string {
	return rd.Name
}

// DHCID represents the RDATA of an DHCID RR.
//
// Conflicts can arise if multiple DHCP clients wish to use the same DNS name
// or a DHCP client attempts to use a name added for another purpose.  To
// resolve such conflicts, [1] proposes storing client identifiers in the DNS
// to unambiguously associate domain names with the DHCP clients using them.
// In the interest of clarity, it is preferable for this DHCP information to
// use a distinct RR type.  This memo defines a distinct RR for this purpose
// for use by DHCP clients or servers: the "DHCID" RR.  In order to obscure
// potentially sensitive client identifying information, the data stored is the
// result of a one-way SHA-256 hash computation.  The hash includes information
// from the DHCP client's message as well as the domain name itself, so that
// the data stored in the DHCID RR will be dependent on both the client
// identification used in the DHCP protocol interaction and the domain name.
// This means that the DHCID RDATA will vary if a single client is associated
// over time with more than one name.  This makes it difficult to 'track' a
// client as it is associated with various domain names.
type DHCID struct {
	Data []byte
}

// SetData computes and sets d.Data as per RFC4701/3.3-3.5.  SetData supports
// only SHA-256 (digest type code 1).
//
// See also TestDHCID in all_test.go for examples.
func (rd *DHCID) SetData(identifierType uint16, identifier []byte, fqdn string) {
	w := dns.NewWirebuf()
	w.Buf = identifier
	w.DisableCompression()
	dns.DomainName(dns.RootedName(fqdn)).Encode(w)
	h := sha256.New()
	h.Write(w.Buf)
	rd.Data = h.Sum([]byte{byte(identifierType >> 8), byte(identifierType), 1})

}

// Implementation of dns.Wirer
func (rd DHCID) Encode(b *dns.Wirebuf) {
	b.Buf = append(b.Buf, rd.Data...)
}

// Implementation of dns.Wirer
func (rd *DHCID) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	n := len(b) - *pos
	if n <= 0 {
		return fmt.Errorf("(*DHCID).Decode: no key data")
	}
	rd.Data = make([]byte, n)
	copy(rd.Data, b[*pos:])
	*pos += n

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataDHCID, rd)
	}
	return
}

func (rd DHCID) String() string {
	return string(strutil.Base64Encode(rd.Data))
}

// DNAME holds the zone DNAME RData
type DNAME struct {
	Name string
}

// Implementation of dns.Wirer
func (rd DNAME) Encode(b *dns.Wirebuf) {
	(dns.DomainName)(rd.Name).Encode(b)
}

// Implementation of dns.Wirer
func (rd *DNAME) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&rd.Name).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataDNAME, rd)
	}
	return
}

func (rd DNAME) String() string {
	return rd.Name
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
	AlgorithmIndirect AlgorithmType = iota + 246 // 252
	AlgorithmPrivateDNS
	AlgorithmPrivateOID
	AlgorithmReserved1255
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

func (c Class) String() (s string) {
	var ok bool
	if s, ok = classStr[c]; !ok {
		return fmt.Sprintf("CLASS%d", uint16(c))
	}
	return
}

// Implementation of dns.Wirer
func (c Class) Encode(b *dns.Wirebuf) {
	dns.Octets2(c).Encode(b)
}

// Implementation of dns.Wirer
func (c *Class) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(c).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffClass, *c)
	}
	return
}

// DLV represents DLV RR RDATA [RFC4431]. The DLV resource record has exactly
// the same wire and presentation formats as the DS resource record, defined in
// RFC 4034, Section 5.  It uses the same IANA-assigned values in the algorithm
// and digest type fields as the DS record.  (Those IANA registries are known
// as the "DNS Security Algorithm Numbers" and "DS RR Type Algorithm Numbers"
// registries.)
//
// The DLV record is a normal DNS record type without any special processing
// requirements.  In particular, the DLV record does not inherit any of the
// special processing or handling requirements of the DS record type (described
// in Section 3.1.4.1 of RFC 4035).  Unlike the DS record, the DLV record may
// not appear on the parent's side of a zone cut.  A DLV record may, however,
// appear at the apex of a zone.
type DLV struct {
	// The key tag is calculated as specified in RFC 2535
	KeyTag uint16
	// Algorithm MUST be allowed to sign DNS data
	Algorithm AlgorithmType
	// The digest type is an identifier for the digest algorithm used
	DigestType HashAlgorithm
	// The digest is calculated over the
	// canonical name of the delegated domain name followed by the whole
	// RDATA of the KEY record (all four fields)
	Digest []byte
}

// Implementation of dns.Wirer
func (rd *DLV) Encode(b *dns.Wirebuf) {
	dns.Octets2(rd.KeyTag).Encode(b)
	dns.Octet(rd.Algorithm).Encode(b)
	dns.Octet(rd.DigestType).Encode(b)
	b.Buf = append(b.Buf, rd.Digest...)
}

// Implementation of dns.Wirer
func (rd *DLV) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&rd.KeyTag).Decode(b, pos, sniffer); err != nil {
		return
	}
	if err = (*dns.Octet)(&rd.Algorithm).Decode(b, pos, sniffer); err != nil {
		return
	}
	if err = (*dns.Octet)(&rd.DigestType).Decode(b, pos, sniffer); err != nil {
		return
	}
	var n int
	switch rd.DigestType {
	case HashAlgorithmSHA1:
		n = 20
	default:
		return fmt.Errorf("unsupported digest type %d", rd.DigestType)
	}

	end := *pos + n
	if end > len(b) {
		return fmt.Errorf("(*rr.DLV).Decode() - buffer underflow")
	}
	rd.Digest = append([]byte{}, b[*pos:end]...)
	*pos = end
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataDLV, rd)
	}
	return
}

func (rd *DLV) String() string {
	if asserts && len(rd.Digest) == 0 {
		panic("internal error")
	}

	return fmt.Sprintf("%d %d %d %s", rd.KeyTag, rd.Algorithm, rd.DigestType, hex.EncodeToString(rd.Digest))
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
func (rd *DNSKEY) Encode(b *dns.Wirebuf) {
	dns.Octets2(rd.Flags).Encode(b)
	dns.Octet(rd.Protocol).Encode(b)
	dns.Octet(rd.Algorithm).Encode(b)
	b.Buf = append(b.Buf, rd.Key...)
}

// Implementation of dns.Wirer
func (rd *DNSKEY) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&rd.Flags).Decode(b, pos, sniffer); err != nil {
		return
	}
	if err = (*dns.Octet)(&rd.Protocol).Decode(b, pos, sniffer); err != nil {
		return
	}
	if err = (*dns.Octet)(&rd.Algorithm).Decode(b, pos, sniffer); err != nil {
		return
	}
	n := len(b) - *pos
	if n <= 0 {
		return fmt.Errorf("(*DNSKEY).Decode: no key data")
	}
	rd.Key = make([]byte, n)
	copy(rd.Key, b[*pos:])
	*pos += n
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataDNSKEY, rd)
	}
	return
}

func (rd *DNSKEY) String() string {
	return fmt.Sprintf("%d %d %d %s", rd.Flags, rd.Protocol, rd.Algorithm, strutil.Base64Encode(rd.Key))
}

// The delegation signer (DS) resource record (RR) is inserted at a zone
// cut (i.e., a delegation point) to indicate that the delegated zone is
// digitally signed and that the delegated zone recognizes the indicated
// key as a valid zone key for the delegated zone. (RFC 3658)
type DS struct {
	// The key tag is calculated as specified in RFC 2535
	KeyTag uint16
	// Algorithm MUST be allowed to sign DNS data
	Algorithm AlgorithmType
	// The digest type is an identifier for the digest algorithm used
	DigestType HashAlgorithm
	// The digest is calculated over the
	// canonical name of the delegated domain name followed by the whole
	// RDATA of the KEY record (all four fields)
	Digest []byte
}

// Implementation of dns.Wirer
func (rd *DS) Encode(b *dns.Wirebuf) {
	dns.Octets2(rd.KeyTag).Encode(b)
	dns.Octet(rd.Algorithm).Encode(b)
	dns.Octet(rd.DigestType).Encode(b)
	b.Buf = append(b.Buf, rd.Digest...)
}

// Implementation of dns.Wirer
func (rd *DS) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&rd.KeyTag).Decode(b, pos, sniffer); err != nil {
		return
	}
	if err = (*dns.Octet)(&rd.Algorithm).Decode(b, pos, sniffer); err != nil {
		return
	}
	if err = (*dns.Octet)(&rd.DigestType).Decode(b, pos, sniffer); err != nil {
		return
	}
	var n int
	switch rd.DigestType {
	case HashAlgorithmSHA1:
		n = 20
	default:
		return fmt.Errorf("unsupported digest type %d", rd.DigestType)
	}

	end := *pos + n
	if end > len(b) {
		return fmt.Errorf("(*rr.DS).Decode() - buffer underflow")
	}
	rd.Digest = append([]byte{}, b[*pos:end]...)
	*pos = end
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataDS, rd)
	}
	return
}

func (rd *DS) String() string {
	if asserts && len(rd.Digest) == 0 {
		panic("internal error")
	}

	return fmt.Sprintf("%d %d %d %s", rd.KeyTag, rd.Algorithm, rd.DigestType, hex.EncodeToString(rd.Digest))
}

type ip4 net.IP

// Implementation of dns.Wirer
func (ip ip4) Encode(b *dns.Wirebuf) {
	b4 := net.IP(ip).To4()
	if asserts {
		if b4 == nil {
			panic(fmt.Errorf("%s is not an IPv4 address", net.IP(ip)))
		}
	}
	b.Buf = append(b.Buf, b4...)
}

// Implementation of dns.Wirer
func (ip *ip4) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p := *pos
	if p+4 > len(b) {
		return fmt.Errorf("(*rr.ip4).Decode() - buffer underflow")
	}

	p0 := &b[p]
	*ip = ip4(net.IPv4(b[p], b[p+1], b[p+2], b[p+3]))
	*pos = p + 4
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffIPV4, ip)
	}
	return
}

type ip6 net.IP

// Implementation of dns.Wirer
func (ip ip6) Encode(b *dns.Wirebuf) {
	b16 := net.IP(ip).To16()
	if asserts {
		if b16 == nil {
			panic(fmt.Errorf("%s is not an IPv6 address", ip))
		}
	}
	b.Buf = append(b.Buf, b16...)
}

// Implementation of dns.Wirer
func (ip *ip6) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p := *pos
	if p+16 > len(b) {
		return fmt.Errorf("(*rr.ip6).Decode() - buffer underflow")
	}

	p0 := &b[p]
	*ip = make([]byte, 16)
	copy(*ip, b[p:])
	*pos = p + 16
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffIPV6, ip)
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
func (rd *GPOS) Encode(b *dns.Wirebuf) {
	var s dns.CharString
	s = dns.CharString(fmt.Sprintf("%f", rd.Longitude))
	s.Encode(b)
	s = dns.CharString(fmt.Sprintf("%f", rd.Latitude))
	s.Encode(b)
	s = dns.CharString(fmt.Sprintf("%f", rd.Altitude))
	s.Encode(b)
}

// Implementation of dns.Wirer
func (rd *GPOS) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	var s dns.CharString

	if err = s.Decode(b, pos, sniffer); err != nil {
		return
	}

	if _, err = fmt.Sscanf(string(s), "%f", &rd.Longitude); err != nil {
		return
	}

	if err = s.Decode(b, pos, sniffer); err != nil {
		return
	}

	if _, err = fmt.Sscanf(string(s), "%f", &rd.Latitude); err != nil {
		return
	}

	if err = s.Decode(b, pos, sniffer); err != nil {
		return
	}

	if _, err = fmt.Sscanf(string(s), "%f", &rd.Altitude); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataGPOS, rd)
	}
	return
}

func (rd *GPOS) String() string {
	return fmt.Sprintf("%f %f %f", rd.Longitude, rd.Latitude, rd.Altitude)
}

// HINFO records are used to acquire general information about a host.  The
// main use is for protocols such as FTP that can use special procedures when
// talking between machines or operating systems of the same type.
type HINFO struct {
	Cpu string // A <character-string> which specifies the CPU type.
	Os  string // A <character-string> which specifies the operating system type.
}

// Implementation of dns.Wirer
func (rd *HINFO) Encode(b *dns.Wirebuf) {
	(dns.CharString)(rd.Cpu).Encode(b)
	(dns.CharString)(rd.Os).Encode(b)
}

// Implementation of dns.Wirer
func (rd *HINFO) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.CharString)(&rd.Cpu).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.CharString)(&rd.Os).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataHINFO, rd)
	}
	return
}

func (rd *HINFO) String() string {
	return fmt.Sprintf(`"%s" "%s"`, quote(rd.Cpu), quote(rd.Os))
}

// HIP represents the RDATA of a HIP RR. This RR allows a HIP node to store in
// the DNS its Host Identity (HI, the public component of the node
// public-private key pair), Host Identity Tag (HIT, a truncated hash of its
// public key), and the Domain Names of its rendezvous servers (RVSs).
type HIP struct {
	// The PK algorithm field indicates the public key cryptographic
	// algorithm and the implied public key field format.  This is an 8-bit
	// unsigned integer.  This document reuses the values defined for the
	// 'algorithm type' of the IPSECKEY RR [RFC4025].
	PKAlgorithm IPSECKEYAlgorithm
	// Host identity tag
	HIT []byte
	// Both of the public key types defined in this document (RSA and DSA)
	// reuse the public key formats defined for the IPSECKEY RR [RFC4025].
	//
	// The DSA key format is defined in RFC 2536 [RFC2536].
	//
	// The RSA key format is defined in RFC 3110 [RFC3110] and the RSA key
	// size limit (4096 bits) is relaxed in the IPSECKEY RR [RFC4025]
	// specification.
	PublicKey []byte
	// The Rendezvous Servers field indicates one or more variable length
	// wire-encoded domain names of rendezvous server(s), as described in
	// Section 3.3 of RFC 1035 [RFC1035].  The wire-encoded format is self-
	// describing, so the length is implicit.  The domain names MUST NOT be
	// compressed.  The rendezvous server(s) are listed in order of
	// preference (i.e., first rendezvous server(s) are preferred),
	// defining an implicit order amongst rendezvous servers of a single
	// RR.  When multiple HIP RRs are present at the same owner name, this
	// implicit order of rendezvous servers within an RR MUST NOT be used
	// to infer a preference order between rendezvous servers stored in
	// different RRs.
	RendezvousServers []string
}

// Implementation of dns.Wirer
func (rd *HIP) Encode(b *dns.Wirebuf) {
	//  0                   1                   2                   3
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |  HIT length   | PK algorithm  |          PK length            |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                                                               |
	// ~                           HIT                                 ~
	// |                                                               |
	// +                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                     |                                         |
	// +-+-+-+-+-+-+-+-+-+-+-+                                         +
	// |                           Public Key                          |
	// ~                                                               ~
	// |                                                               |
	// +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                               |                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
	// |                                                               |
	// ~                       Rendezvous Servers                      ~
	// |                                                               |
	// +             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |             |
	// +-+-+-+-+-+-+-+
	dns.Octet(len(rd.HIT)).Encode(b)
	dns.Octet(rd.PKAlgorithm).Encode(b)
	dns.Octets2(len(rd.PublicKey)).Encode(b)
	b.Buf = append(b.Buf, rd.HIT...)
	b.Buf = append(b.Buf, rd.PublicKey...)
	b.DisableCompression()
	for _, v := range rd.RendezvousServers {
		dns.DomainName(v).Encode(b)
	}
	b.EnableCompression()

}

// Implementation of dns.Wirer
func (rd *HIP) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	var hitLength dns.Octet
	if err = hitLength.Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octet)(&rd.PKAlgorithm).Decode(b, pos, sniffer); err != nil {
		return
	}

	var pkLength dns.Octets2
	if err = pkLength.Decode(b, pos, sniffer); err != nil {
		return
	}

	if *pos+int(hitLength) > len(b)+1 {
		return fmt.Errorf("(*rr.HIP).Decode() - buffer underflow")
	}

	rd.HIT = make([]byte, int(hitLength))
	copy(rd.HIT, b[*pos:*pos+int(hitLength)])
	*pos += int(hitLength)

	if *pos+int(pkLength) > len(b)+1 {
		return fmt.Errorf("(*rr.HIP).Decode() - buffer underflow")
	}

	rd.PublicKey = make([]byte, int(pkLength))
	copy(rd.PublicKey, b[*pos:*pos+int(pkLength)])
	*pos += int(pkLength)

	rd.RendezvousServers = nil
	for *pos < len(b) {
		var s dns.DomainName
		if err = s.Decode(b, pos, sniffer); err != nil {
			return
		}

		rd.RendezvousServers = append(rd.RendezvousServers, string(s))
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataHIP, rd)
	}
	return
}

func (rd *HIP) String() string {
	a := []string{}
	for _, v := range rd.RendezvousServers {
		a = append(a, v)
	}
	s := ""
	if len(a) != 0 {
		s = " " + strings.Join(a, " ")
	}
	return fmt.Sprintf("%d %x %s%s", rd.PKAlgorithm, rd.HIT, strutil.Base64Encode(rd.PublicKey), s)
}

// IPSECKEYAlgorithm is the type of the IPSECKEY RData Algorithm field
type IPSECKEYAlgorithm byte

// Values of IPSECKEYAlgorithm
const (
	IPSECKEYAlgorithmNone IPSECKEYAlgorithm = iota
	IPSECKEYAlgorithmDSA
	IPSECKEYAlgorithmRSA
)

// GatewayType type is the type of the IPSECKEY GatewayType field.
type GatewayType byte

// Values of GatewayType
const (
	GatewayNone GatewayType = iota
	GatewayIPV4
	GatewayIPV6
	GatewayDomain
)

// IPSECKEY type represents the IPSECKEY RR RData.  The IPSECKEY resource
// record (RR) is used to publish a public key that is to be associated with a
// Domain Name System (DNS) [1] name for use with the IPsec protocol suite.
// This can be the public key of a host, network, or application (in the case
// of per-port keying).
//
// NOTE: IPSECKEY.Encode(), .String() will panic and/or fail to perform
// properly if GatewayType doesn't reflect the appropriate type stored in
// Gateway. Use the SetGateway helper to avoid such situation.
type IPSECKEY struct {
	// This is an 8-bit precedence for this record.  It is interpreted in
	// the same way as the PREFERENCE field described in section 3.3.9 of
	// RFC 1035.
	//
	// Gateways listed in IPSECKEY records with lower precedence are to be
	// attempted first.  Where there is a tie in precedence, the order
	// should be non-deterministic.
	Precedence byte
	// The gateway type field indicates the format of the information that
	// is stored in the gateway field.
	//
	// The following values are defined:
	// 0  No gateway is present.
	//    Gateway == nil
	// 1  A 4-byte IPv4 address is present.
	//    Gateway.(type) == net.IP w/ len() == 4
	// 2  A 16-byte IPv6 address is present.
	//    Gateway.(type) == net.IP w/ len() == 16
	// 3  A wire-encoded domain name is present.  The wire-encoded format is
	//    self-describing, so the length is implicit.  The domain name MUST
	//    NOT be compressed.  (See Section 3.3 of RFC 1035.)
	//    Gateway.(type) == dns.DomainName
	GatewayType GatewayType
	// The algorithm type field identifies the public key's cryptographic
	// algorithm and determines the format of the public key field.
	//
	// A value of 0 indicates that no key is present.
	//
	// The following values are defined:
	// 1  A DSA key is present, in the format defined in RFC 2536.
	// 2  A RSA key is present, in the format defined in RFC 3110.
	Algorithm IPSECKEYAlgorithm
	// The gateway field indicates a gateway to which an IPsec tunnel may be
	// created in order to reach the entity named by this resource record.
	//
	// There are three formats:
	//
	// A 32-bit IPv4 address is present in the gateway field.  The data
	// portion is an IPv4 address as described in section 3.4.1 of RFC 1035
	// [2].  This is a 32-bit number in network byte order.
	//
	// A 128-bit IPv6 address is present in the gateway field.  The data
	// portion is an IPv6 address as described in section 2.2 of RFC 3596
	// [12].  This is a 128-bit number in network byte order.
	//
	// The gateway field is a normal wire-encoded domain name, as described
	// in section 3.3 of RFC 1035 [2].  Compression MUST NOT be used.
	Gateway interface{}
	// Both the public key types defined in this document (RSA and DSA)
	// inherit their public key formats from the corresponding KEY RR
	// formats.  Specifically, the public key field contains the
	// algorithm-specific portion of the KEY RR RDATA, which is all the KEY
	// RR DATA after the first four octets.  This is the same portion of the
	// KEY RR that must be specified by documents that define a DNSSEC
	// algorithm.  Those documents also specify a message digest to be used
	// for generation of SIG RRs; that specification is not relevant for
	// IPSECKEY RRs.
	//
	// Future algorithms, if they are to be used by both DNSSEC (in the KEY
	// RR) and IPSECKEY, are likely to use the same public key encodings in
	// both records.  Unless otherwise specified, the IPSECKEY public key
	// field will contain the algorithm-specific portion of the KEY RR RDATA
	// for the corresponding algorithm.  The algorithm must still be
	// designated for use by IPSECKEY, and an IPSECKEY algorithm type number
	// (which might be different from the DNSSEC algorithm number) must be
	// assigned to it.
	//
	// The DSA key format is defined in RFC 2536.
	//
	// The RSA key format is defined in RFC 3110, with the following
	// changes:
	//
	// The earlier definition of RSA/MD5 in RFC 2065 limited the exponent
	// and modulus to 2552 bits in length.  RFC 3110 extended that limit to
	// 4096 bits for RSA/SHA1 keys.  The IPSECKEY RR imposes no length
	// limit on RSA public keys, other than the 65535 octet limit imposed
	// by the two-octet length encoding.  This length extension is
	// applicable only to IPSECKEY; it is not applicable to KEY RRs.
	PublicKey []byte
}

// SetGeteway will safely set d.Gateway and d.GatewayType or return an error
// otherwise if g type is not (nil or net.IP or a string).
func (rd *IPSECKEY) SetGateway(g interface{}) (t GatewayType, err error) {
	switch x := g.(type) {
	default:
		err = fmt.Errorf("(*IPSECKEY).SetGateway(%T): unsupported", g)
	case nil:
		rd.GatewayType, rd.Gateway = GatewayNone, nil
	case net.IP:
		if ip := x.To4(); ip != nil {
			rd.GatewayType, rd.Gateway = GatewayIPV4, ip
			break
		}

		if ip := x.To16(); ip != nil {
			rd.GatewayType, rd.Gateway = GatewayIPV6, ip
			break
		}

		err = fmt.Errorf("(*IPSECKEY).SetGateway(%#v): unsupported", g)
	case string:
		rd.GatewayType, rd.Gateway = GatewayDomain, dns.DomainName(x)
	case dns.DomainName:
		rd.GatewayType, rd.Gateway = GatewayDomain, string(x)
	}

	t = rd.GatewayType
	return
}

// Implementation of dns.Wirer
func (rd *IPSECKEY) Encode(b *dns.Wirebuf) {
	dns.Octet(rd.Precedence).Encode(b)
	dns.Octet(rd.GatewayType).Encode(b)
	dns.Octet(rd.Algorithm).Encode(b)
	switch rd.GatewayType {
	case GatewayNone:
		// nop
	case GatewayIPV4:
		b.Buf = append(b.Buf, rd.Gateway.(net.IP).To4()...)
	case GatewayIPV6:
		b.Buf = append(b.Buf, rd.Gateway.(net.IP).To16()...)
	case GatewayDomain:
		b.DisableCompression()
		dns.DomainName(rd.Gateway.(string)).Encode(b)
		b.EnableCompression()
	}
	b.Buf = append(b.Buf, rd.PublicKey...)
}

// Implementation of dns.Wirer
func (rd *IPSECKEY) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octet)(&rd.Precedence).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octet)(&rd.GatewayType).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octet)(&rd.Algorithm).Decode(b, pos, sniffer); err != nil {
		return
	}

	switch rd.GatewayType {
	default:
		return fmt.Errorf("(*IPSECKEY.Decode(): Unknown GatewayType %d", rd.GatewayType)
	case GatewayNone:
		// nop
	case GatewayIPV4:
		if *pos+4 > len(b)+1 {
			return errors.New("(*IPSECKEY.Decode(): Buffer undeflow")
		}

		rd.Gateway = net.IP(append([]byte{}, b[*pos:*pos+4]...))
		*pos += 4
	case GatewayIPV6:
		if *pos+16 > len(b)+1 {
			return errors.New("(*IPSECKEY.Decode(): Buffer undeflow")
		}

		rd.Gateway = net.IP(append([]byte{}, b[*pos:*pos+16]...))
		*pos += 16
	case GatewayDomain:
		var n dns.DomainName
		if err = (*dns.DomainName)(&n).Decode(b, pos, sniffer); err != nil {
			return
		}

		rd.Gateway = string(n)
	}

	n := len(b) - *pos
	if n <= 0 {
		return fmt.Errorf("(*IPSECKEY).Decode: no key data")
	}

	rd.PublicKey = make([]byte, n)
	copy(rd.PublicKey, b[*pos:])
	*pos += n
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataIPSECKEY, rd)
	}
	return
}

func (rd *IPSECKEY) String() (s string) {
	defer func() {
		if e := recover(); e != nil {
			s = fmt.Sprintf("; (*IPSECKEY).String(%#v): %v", rd, e)
		}
	}()

	switch rd.GatewayType {
	default:
		panic(fmt.Errorf("(*IPSECKEY.Decode(): Unknown GatewayType %d", rd.GatewayType))
	case GatewayNone:
		return fmt.Sprintf("%d %d %d . %s", rd.Precedence, rd.GatewayType, rd.Algorithm, strutil.Base64Encode(rd.PublicKey))
	case GatewayIPV4, GatewayIPV6:
		return fmt.Sprintf("%d %d %d %s %s", rd.Precedence, rd.GatewayType, rd.Algorithm, rd.Gateway.(net.IP), strutil.Base64Encode(rd.PublicKey))
	case GatewayDomain:
		return fmt.Sprintf("%d %d %d %s %s", rd.Precedence, rd.GatewayType, rd.Algorithm, rd.Gateway.(string), strutil.Base64Encode(rd.PublicKey))
	}
	panic("unreachable")
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
func (rd *ISDN) Encode(b *dns.Wirebuf) {
	(dns.CharString)(rd.ISDN).Encode(b)
	(dns.CharString)(rd.Sa).Encode(b)
}

// Implementation of dns.Wirer
func (rd *ISDN) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.CharString)(&rd.ISDN).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.CharString)(&rd.Sa).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataISDN, rd)
	}
	return
}

func (rd *ISDN) String() string {
	return fmt.Sprintf(`"%s" "%s"`, quote(rd.ISDN), quote(rd.Sa))
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
func (rd *KEY) Encode(b *dns.Wirebuf) {
	dns.Octets2(rd.Flags).Encode(b)
	dns.Octet(rd.Protocol).Encode(b)
	dns.Octet(rd.Algorithm).Encode(b)
	b.Buf = append(b.Buf, rd.Key...)
}

// Implementation of dns.Wirer
func (rd *KEY) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&rd.Flags).Decode(b, pos, sniffer); err != nil {
		return
	}
	if err = (*dns.Octet)(&rd.Protocol).Decode(b, pos, sniffer); err != nil {
		return
	}
	if err = (*dns.Octet)(&rd.Algorithm).Decode(b, pos, sniffer); err != nil {
		return
	}
	n := len(b) - *pos
	if n <= 0 {
		return fmt.Errorf("(*KEY).Decode: no key data")
	}
	rd.Key = make([]byte, n)
	copy(rd.Key, b[*pos:])
	*pos += n
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataKEY, rd)
	}
	return
}

func (rd *KEY) String() string {
	return fmt.Sprintf("%d %d %d %s", rd.Flags, rd.Protocol, rd.Algorithm, strutil.Base64Encode(rd.Key))
}

type KX struct {
	// A 16 bit non-negative integer which specifies the preference given
	// to this RR among other KX records at the same owner.  Lower values
	// are preferred.
	Preference uint16
	// A <domain-name> which specifies a host willing to act as a mail
	// exchange for the owner name.
	Exchanger string
}

// Implementation of dns.Wirer
func (rd *KX) Encode(b *dns.Wirebuf) {
	b.DisableCompression()
	defer b.EnableCompression()

	dns.Octets2(rd.Preference).Encode(b)
	dns.DomainName(rd.Exchanger).Encode(b)
}

// Implementation of dns.Wirer
func (rd *KX) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&rd.Preference).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.DomainName)(&rd.Exchanger).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataKX, rd)
	}
	return
}

func (rd *KX) String() string {
	return fmt.Sprintf("%d %s", rd.Preference, rd.Exchanger)
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
func (rd *LOC) Encode(b *dns.Wirebuf) {
	dns.Octet(rd.Version).Encode(b)
	dns.Octet(rd.Size).Encode(b)
	dns.Octet(rd.HorizPre).Encode(b)
	dns.Octet(rd.VertPre).Encode(b)
	dns.Octets4(rd.Longitude).Encode(b)
	dns.Octets4(rd.Latitude).Encode(b)
	dns.Octets4(rd.Altitude).Encode(b)
}

// Implementation of dns.Wirer
func (rd *LOC) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if (*dns.Octet)(&rd.Version).Decode(b, pos, sniffer); err != nil {
		return
	}

	if (*dns.Octet)(&rd.Size).Decode(b, pos, sniffer); err != nil {
		return
	}

	if (*dns.Octet)(&rd.HorizPre).Decode(b, pos, sniffer); err != nil {
		return
	}

	if (*dns.Octet)(&rd.VertPre).Decode(b, pos, sniffer); err != nil {
		return
	}

	if (*dns.Octets4)(&rd.Longitude).Decode(b, pos, sniffer); err != nil {
		return
	}

	if (*dns.Octets4)(&rd.Latitude).Decode(b, pos, sniffer); err != nil {
		return
	}

	if (*dns.Octets4)(&rd.Altitude).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataLOC, rd)
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

func (rd *LOC) DecAlt() (cm int64) {
	return int64(rd.Altitude) - 10000000
}

func (rd *LOC) EncAlt(cm int64) {
	rd.Altitude = uint32(cm + 10000000)
}

func (rd *LOC) DecDMTS(x uint32) (deg, min, ts int, positive bool) {
	deg = rd.Degrees(x)
	if positive = deg >= 0; !positive {
		deg = -deg
	}
	min = rd.Minutes(x)
	ts = rd.ThousandsSecs(x)
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

func (rd *LOC) String() string {
	latDeg, latMin, latTS, north := rd.DecDMTS(rd.Latitude)
	lonDeg, lonMin, lonTS, east := rd.DecDMTS(rd.Longitude)
	altM := rd.DecAlt()
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
	siz, hp, vp := rd.DecPrec(rd.Size), rd.DecPrec(rd.HorizPre), rd.DecPrec(rd.VertPre)
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
func (rd *MB) Encode(b *dns.Wirebuf) {
	dns.DomainName(rd.MADNAME).Encode(b)
}

// Implementation of dns.Wirer
func (rd *MB) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&rd.MADNAME).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataMB, rd)
	}
	return
}

func (rd *MB) String() string {
	return rd.MADNAME
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
func (rd *MD) Encode(b *dns.Wirebuf) {
	dns.DomainName(rd.MADNAME).Encode(b)
}

// Implementation of dns.Wirer
func (rd *MD) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&rd.MADNAME).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataMD, rd)
	}
	return
}

func (rd *MD) String() string {
	return rd.MADNAME
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
func (rd *MF) Encode(b *dns.Wirebuf) {
	dns.DomainName(rd.MADNAME).Encode(b)
}

// Implementation of dns.Wirer
func (rd *MF) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&rd.MADNAME).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataMF, rd)
	}
	return
}

func (rd *MF) String() string {
	return rd.MADNAME
}

// MG records cause no additional section processing.
type MG struct {
	// A <domain-name> which specifies a mailbox which is a member of the
	// mail group specified by the domain name.
	MGNAME string
}

// Implementation of dns.Wirer
func (rd *MG) Encode(b *dns.Wirebuf) {
	dns.DomainName(rd.MGNAME).Encode(b)
}

// Implementation of dns.Wirer
func (rd *MG) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&rd.MGNAME).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataMG, rd)
	}
	return
}

func (rd *MG) String() string {
	return rd.MGNAME
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
func (rd *MINFO) Encode(b *dns.Wirebuf) {
	(dns.DomainName)(rd.RMAILBX).Encode(b)
	(dns.DomainName)(rd.EMAILBX).Encode(b)
}

// Implementation of dns.Wirer
func (rd *MINFO) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&rd.RMAILBX).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.DomainName)(&rd.EMAILBX).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataMINFO, rd)
	}
	return
}

func (rd *MINFO) String() string {
	return fmt.Sprintf("%s %s", rd.RMAILBX, rd.EMAILBX)
}

// MR records cause no additional section processing.  The main use for MR is
// as a forwarding entry for a user who has moved to a different mailbox.
type MR struct {
	// A <domain-name> which specifies a mailbox which is the proper rename
	// of the specified mailbox.
	NEWNAME string
}

// Implementation of dns.Wirer
func (rd *MR) Encode(b *dns.Wirebuf) {
	dns.DomainName(rd.NEWNAME).Encode(b)
}

// Implementation of dns.Wirer
func (rd *MR) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&rd.NEWNAME).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataMR, rd)
	}
	return
}

func (rd *MR) String() string {
	return rd.NEWNAME
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
func (rd *MX) Encode(b *dns.Wirebuf) {
	dns.Octets2(rd.Preference).Encode(b)
	dns.DomainName(rd.Exchange).Encode(b)
}

// Implementation of dns.Wirer
func (rd *MX) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&rd.Preference).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.DomainName)(&rd.Exchange).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataMX, rd)
	}
	return
}

func (rd *MX) String() string {
	return fmt.Sprintf("%d %s", rd.Preference, rd.Exchange)
}

type NAPTR struct {
	// A 16-bit unsigned integer specifying the order in which the NAPTR
	// records MUST be processed in order to accurately represent the
	// ordered list of Rules.  The ordering is from lowest to highest.  If
	// two records have the same order value then they are considered to be
	// the same rule and should be selected based on the combination of the
	// Preference values and Services offered.
	Order uint16

	// Although it is called "preference" in deference to DNS terminology,
	// this field is equivalent to the Priority value in the DDDS
	// Algorithm.  It is a 16-bit unsigned integer that specifies the order
	// in which NAPTR records with equal Order values SHOULD be processed,
	// low numbers being processed before high numbers.  This is similar to
	// the preference field in an MX record, and is used so domain
	// administrators can direct clients towards more capable hosts or
	// lighter weight protocols.  A client MAY look at records with higher
	// preference values if it has a good reason to do so such as not
	// supporting some protocol or service very well.
	// 
	// The important difference between Order and Preference is that once a
	// match is found the client MUST NOT consider records with a different
	// Order but they MAY process records with the same Order but different
	// Preferences.  The only exception to this is noted in the second
	// important Note in the DDDS algorithm specification concerning
	// allowing clients to use more complex Service determination between
	// steps 3 and 4 in the algorithm.  Preference is used to give
	// communicate a higher quality of service to rules that are considered
	// the same from an authority standpoint but not from a simple load
	// balancing standpoint.
	// 
	// It is important to note that DNS contains several load balancing
	// mechanisms and if load balancing among otherwise equal services
	// should be needed then methods such as SRV records or multiple A
	// records should be utilized to accomplish load balancing.
	Preference uint16

	// A <character-string> containing flags to control aspects of the
	// rewriting and interpretation of the fields in the record.  Flags are
	// single characters from the set A-Z and 0-9.  The case of the
	// alphabetic characters is not significant.  The field can be empty.
	// 
	// It is up to the Application specifying how it is using this Database
	// to define the Flags in this field.  It must define which ones are
	// terminal and which ones are not.
	Flags string

	// A <character-string> that specifies the Service Parameters
	// applicable to this this delegation path.  It is up to the
	// Application Specification to specify the values found in this field.
	Services string

	// A <character-string> containing a substitution expression that is
	// applied to the original string held by the client in order to
	// construct the next domain name to lookup.  See the DDDS Algorithm
	// specification for the syntax of this field.
	// 
	// As stated in the DDDS algorithm, The regular expressions MUST NOT be
	// used in a cumulative fashion, that is, they should only be applied
	// to the original string held by the client, never to the domain name
	// produced by a previous NAPTR rewrite.  The latter is tempting in
	// some applications but experience has shown such use to be extremely
	// fault sensitive, very error prone, and extremely difficult to debug.
	Regexp string

	// A <domain-name> which is the next domain-name to query for depending
	// on the potential values found in the flags field.  This field is
	// used when the regular expression is a simple replacement operation.
	// Any value in this field MUST be a fully qualified domain-name.  Name
	// compression is not to be used for this field.
	// 
	// This field and the REGEXP field together make up the Substitution
	// Expression in the DDDS Algorithm.  It is simply a historical
	// optimization specifically for DNS compression that this field
	// exists.  The fields are also mutually exclusive.  If a record is
	// returned that has values for both fields then it is considered to be
	// in error and SHOULD be either ignored or an error returned.
	Replacement string
}

// Implementation of dns.Wirer
func (rd *NAPTR) Encode(b *dns.Wirebuf) {
	dns.Octets2(rd.Order).Encode(b)
	dns.Octets2(rd.Preference).Encode(b)
	dns.CharString(rd.Flags).Encode(b)
	dns.CharString(rd.Services).Encode(b)
	dns.CharString(rd.Regexp).Encode(b)
	dns.DomainName(rd.Replacement).Encode(b)
}

// Implementation of dns.Wirer
func (rd *NAPTR) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&rd.Order).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octets2)(&rd.Preference).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.CharString)(&rd.Flags).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.CharString)(&rd.Services).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.CharString)(&rd.Regexp).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.DomainName)(&rd.Replacement).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataNAPTR, rd)
	}
	return
}

func (rd *NAPTR) String() string {
	return fmt.Sprintf("%d %d \"%s\" \"%s\" \"%s\" %s", rd.Order, rd.Preference, quote(rd.Flags), quote(rd.Services), quote(rd.Regexp), rd.Replacement)
}

// NODATA is used for negative caching of authoritative answers
// for queried non existent Type/Class combinations.
type NODATA struct {
	Type // The Type for which we are caching the NODATA
}

// Implementation of dns.Wirer
func (rd *NODATA) Encode(b *dns.Wirebuf) {
	rd.Type.Encode(b)
}

// Implementation of dns.Wirer
func (rd *NODATA) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = rd.Type.Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataNODATA, rd)
	}
	return
}

func (rd *NODATA) String() string {
	return fmt.Sprintf("%s", rd.Type)
}

// NXDOMAIN is used for negative caching of authoritave answers 
// for queried non existing domain names.
type NXDOMAIN struct{}

// Implementation of dns.Wirer
func (rd *NXDOMAIN) Encode(b *dns.Wirebuf) {
	// nop
}

// Implementation of dns.Wirer
func (rd *NXDOMAIN) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	// nop
	return
}

func (rd *NXDOMAIN) String() (s string) {
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
func (rd *NS) Encode(b *dns.Wirebuf) {
	dns.DomainName(rd.NSDName).Encode(b)
}

// Implementation of dns.Wirer
func (rd *NS) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&rd.NSDName).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataNS, rd)
	}
	return
}

func (rd *NS) String() string {
	return rd.NSDName
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
func (rd *NSAP) Encode(b *dns.Wirebuf) {
	b.Buf = append(b.Buf, rd.NSAP...)
}

// Implementation of dns.Wirer
func (rd *NSAP) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	if *pos >= len(b) {
		rd.NSAP = []byte{}
		if sniffer != nil {
			sniffer(nil, nil, dns.SniffRDataNSAP, rd)
		}
		return
	}

	p0 := &b[*pos]
	rd.NSAP = append([]byte{}, b[*pos:]...)
	*pos = len(b)
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataNSAP, rd)
	}
	return
}

func (rd *NSAP) String() string {
	return fmt.Sprintf("0x%x", rd.NSAP)
}

// NSAP_PTR has a function analogous to the PTR record used for IP addresses
type NSAP_PTR struct {
	Name string
}

// Implementation of dns.Wirer
func (rd NSAP_PTR) Encode(b *dns.Wirebuf) {
	(dns.DomainName)(rd.Name).Encode(b)
}

// Implementation of dns.Wirer
func (rd *NSAP_PTR) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&rd.Name).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataCNAME, rd)
	}
	return
}

func (rd NSAP_PTR) String() string {
	return rd.Name
}

// HashAlgorithm is the type of the hash algorithm in the NSEC3 RR
type HashAlgorithm byte

// IANA registry for "DNSSEC NSEC3 Hash Algorithms".
// Values of HashAlgorithm.
const (
	HashAlgorithmReserved HashAlgorithm = iota
	HashAlgorithmSHA1
)

// Type NSEC represents NSEC RR RData.  The NSEC resource record lists two
// separate things: the next owner name (in the canonical ordering of the zone)
// that contains authoritative data or a delegation point NS RRset, and the set
// of RR types present at the NSEC RR's owner name [RFC3845].  The complete set
// of NSEC RRs in a zone indicates which authoritative RRsets exist in a zone
// and also form a chain of authoritative owner names in the zone.  This
// information is used to provide authenticated denial of existence for DNS
// data, as described in [RFC4035].
//
// Because every authoritative name in a zone must be part of the NSEC chain,
// NSEC RRs must be present for names containing a CNAME RR.  This is a change
// to the traditional DNS specification [RFC1034], which stated that if a CNAME
// is present for a name, it is the only type allowed at that name.  An RRSIG
// (see Section 3) and NSEC MUST exist for the same name as does a CNAME
// resource record in a signed zone.
//
// See [RFC4035] for discussion of how a zone signer determines precisely which
// NSEC RRs it has to include in a zone.
//
// The NSEC RR is class independent.
//
// The NSEC RR SHOULD have the same TTL value as the SOA minimum TTL field.
// This is in the spirit of negative caching ([RFC2308]).
type NSEC struct {
	// The Next Domain field contains the next owner name (in the canonical
	// ordering of the zone) that has authoritative data or contains a
	// delegation point NS RRset; see Section 6.1 for an explanation of
	// canonical ordering.  The value of the Next Domain Name field in the
	// last NSEC record in the zone is the name of the zone apex (the owner
	// name of the zone's SOA RR).  This indicates that the owner name of
	// the NSEC RR is the last name in the canonical ordering of the zone.
	//
	// A sender MUST NOT use DNS name compression on the Next Domain Name
	// field when transmitting an NSEC RR.
	//
	// Owner names of RRsets for which the given zone is not authoritative
	// (such as glue records) MUST NOT be listed in the Next Domain Name
	// unless at least one authoritative RRset exists at the same owner
	// name.	
	NextDomainName string
	// The Type Bit Maps field identifies the RRset types that exist at the
	// NSEC RR's owner name.
	TypeBitMaps []byte
}

// Implementation of dns.Wirer
func (rd *NSEC) Encode(b *dns.Wirebuf) {
	(dns.DomainName)(rd.NextDomainName).Encode(b)
	b.Buf = append(b.Buf, rd.TypeBitMaps...)
}

// Implementation of dns.Wirer
func (rd *NSEC) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&rd.NextDomainName).Decode(b, pos, sniffer); err != nil {
		return
	}

	end := len(b)
	rd.TypeBitMaps = append([]byte{}, b[*pos:end]...)
	*pos = end
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataNSEC, rd)
	}
	return
}

func (rd *NSEC) String() string {
	types, err := TypesDecode(rd.TypeBitMaps)
	if err != nil {
		panic(err)
	}

	return fmt.Sprintf("%s %s", rd.NextDomainName, TypesString(types))
}

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
func (rd *NSEC3) Encode(b *dns.Wirebuf) {
	rd.NSEC3PARAM.Encode(b)
	n := dns.Octets2(len(rd.NextHashedOwnerName))
	n.Encode(b)
	b.Buf = append(b.Buf, rd.NextHashedOwnerName...)
	b.Buf = append(b.Buf, rd.TypeBitMaps...)
}

// Implementation of dns.Wirer
func (rd *NSEC3) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = rd.NSEC3PARAM.Decode(b, pos, sniffer); err != nil {
		return
	}

	var n dns.Octets2
	if err = n.Decode(b, pos, sniffer); err != nil {
		return
	}

	in := int(n)
	if *pos+in > len(b) {
		return fmt.Errorf("(*rr.NSEC3).Decode() - buffer underflow")
	}

	rd.NextHashedOwnerName = append([]byte{}, b[*pos:*pos+in]...)
	*pos = *pos + in

	// here we (have to) rely on b being sliced exactly at the end of the wire format packet
	end := len(b)
	rd.TypeBitMaps = append([]byte{}, b[*pos:end]...)
	*pos = end
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataNSEC3, rd)
	}
	return
}

func (rd *NSEC3) String() string {
	types, err := TypesDecode(rd.TypeBitMaps)
	if err != nil {
		panic(err)
	}

	return fmt.Sprintf("%s %s %s", rd.NSEC3PARAM.String(), strutil.Base32ExtEncode(rd.NextHashedOwnerName), TypesString(types))
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
func (rd *NSEC3PARAM) Encode(b *dns.Wirebuf) {
	dns.Octet(rd.HashAlgorithm).Encode(b)
	dns.Octet(rd.Flags).Encode(b)
	dns.Octets2(rd.Iterations).Encode(b)
	if asserts && len(rd.Salt) > 255 {
		panic("internal error")
	}
	dns.Octet(len(rd.Salt)).Encode(b)
	b.Buf = append(b.Buf, rd.Salt...)
}

// Implementation of dns.Wirer
func (rd *NSEC3PARAM) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octet)(&rd.HashAlgorithm).Decode(b, pos, sniffer); err != nil {
		return
	}
	if err = (*dns.Octet)(&rd.Flags).Decode(b, pos, sniffer); err != nil {
		return
	}
	if err = (*dns.Octets2)(&rd.Iterations).Decode(b, pos, sniffer); err != nil {
		return
	}
	var n byte
	if err = (*dns.Octet)(&n).Decode(b, pos, sniffer); err != nil {
		return
	}
	p := *pos
	next := p + int(n)
	if next > len(b) {
		return fmt.Errorf("(*rr.NSEC3PARAM).Decode() - buffer underflow")
	}
	rd.Salt = append([]byte{}, b[p:next]...)
	*pos = next
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataNSEC3PARAM, rd)
	}
	return
}

func (rd *NSEC3PARAM) String() string {
	s := hex.EncodeToString(rd.Salt)
	if s == "" {
		s = "-"
	}
	return fmt.Sprintf("%d %d %d %s", rd.HashAlgorithm, rd.Flags, rd.Iterations, s)
}

type NULL struct {
	Data []byte
}

// Implementation of dns.Wirer
func (rd *NULL) Encode(b *dns.Wirebuf) {
	b.Buf = append(b.Buf, rd.Data...)
}

// Implementation of dns.Wirer
func (rd *NULL) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	n := 0
	var p0 *byte
	if *pos < len(b) {
		p0 = &b[*pos]
		n = len(b) - *pos
		rd.Data = make([]byte, n)
		copy(rd.Data, b[*pos:])
	} else {
		rd.Data = []byte{}
		if sniffer != nil {
			sniffer(nil, nil, dns.SniffRDataNULL, rd)
		}
		return
	}

	*pos += n
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataNULL, rd)
	}
	return
}

func (rd *NULL) String() string {
	if len(rd.Data) == 0 {
		return "\\#"
	}

	return fmt.Sprintf("\\# %d %x", len(rd.Data), rd.Data)
}

// OPT_DATA holds an {attribute, value} pair of the OPT RR
type OPT_DATA struct {
	Code uint16
	Data []byte
}

// Implementation of dns.Wirer
func (rd *OPT_DATA) Encode(b *dns.Wirebuf) {
	dns.Octets2(rd.Code).Encode(b)
	dns.Octets2(len(rd.Data)).Encode(b)
	b.Buf = append(b.Buf, rd.Data...)
}

// Implementation of dns.Wirer
func (rd *OPT_DATA) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&rd.Code).Decode(b, pos, sniffer); err != nil {
		return
	}
	var n dns.Octets2
	if err = n.Decode(b, pos, sniffer); err != nil {
		return
	}
	p := *pos
	next := p + int(n)
	if next > len(b) {
		return fmt.Errorf("(*rr.OPT_DATA).Decode() - buffer underflow")
	}
	rd.Data = b[p:next]
	*pos = next
	if next > len(b) {
		sniffer(p0, nil, dns.SniffOPT_DATA, rd)
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffOPT_DATA, rd)
	}
	return
}

func (rd *OPT_DATA) String() string {
	return fmt.Sprintf("%04x:% x", rd.Code, rd.Data)
}

// OPT holds the RFC2671 OPT pseudo RR RData
type OPT struct {
	Values []OPT_DATA
}

// Implementation of dns.Wirer
func (rd *OPT) Encode(b *dns.Wirebuf) {
	for _, v := range rd.Values {
		v.Encode(b)
	}
}

// Implementation of dns.Wirer
func (rd *OPT) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	for *pos < len(b) {
		v := OPT_DATA{}
		if err = v.Decode(b, pos, sniffer); err != nil {
			return
		}

		rd.Values = append(rd.Values, v)
	}
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataOPT, rd)
	}
	return
}

func (rd *OPT) String() string {
	a := make([]string, len(rd.Values))
	for i, v := range rd.Values {
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
func (rd *EXT_RCODE) FromTTL(n int32) {
	rd.RCODE = byte(n >> 24)
	rd.Version = byte(n >> 16)
	rd.Z = uint16(n)
}

// ToTTL returns rd as the value of a RR.TTL
func (rd *EXT_RCODE) ToTTL() int32 {
	return int32(rd.RCODE)<<24 | int32(rd.Version)<<16 | int32(rd.Z)
}

// Implementation of dns.Wirer
func (rd *EXT_RCODE) Encode(b *dns.Wirebuf) {
	n := dns.Octets4(uint32(rd.RCODE<<24) | uint32(rd.Version<<16) | uint32(rd.Z))
	n.Encode(b)
}

// Implementation of dns.Wirer
func (rd *EXT_RCODE) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	var n dns.Octets4
	if err = n.Decode(b, pos, sniffer); err != nil {
		return
	}
	rd.FromTTL(int32(n))
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffEXT_RCODE, rd)
	}
	return
}

func (rd *EXT_RCODE) String() string {
	return fmt.Sprintf("EXT_RCODE:%02xx Ver:%d Z:%d", rd.RCODE, rd.Version, rd.Z)
}

// PTR holds the zone PTR RData
type PTR struct {
	// A <domain-name> which points to some location in the
	// domain name space.
	PTRDName string
}

// Implementation of dns.Wirer
func (rd *PTR) Encode(b *dns.Wirebuf) {
	dns.DomainName(rd.PTRDName).Encode(b)
}

// Implementation of dns.Wirer
func (rd *PTR) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&rd.PTRDName).Decode(b, pos, sniffer); err != nil {
		return
	}
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataPTR, rd)
	}
	return
}

func (rd *PTR) String() string {
	return rd.PTRDName
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
func (rd *PX) Encode(b *dns.Wirebuf) {
	dns.Octets2(rd.Preference).Encode(b)
	dns.DomainName(rd.MAP822).Encode(b)
	dns.DomainName(rd.MAPX400).Encode(b)
}

// Implementation of dns.Wirer
func (rd *PX) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&rd.Preference).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.DomainName)(&rd.MAP822).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.DomainName)(&rd.MAPX400).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataPX, rd)
	}
	return
}

func (rd *PX) String() string {
	return fmt.Sprintf("%d %s %s", rd.Preference, rd.MAP822, rd.MAPX400)
}

// RDATA hodls DNS RR rdata for a unknown/unsupported RR type (RFC3597).
type RDATA []byte

// Implementation of dns.Wirer
func (rd *RDATA) Encode(b *dns.Wirebuf) {
	b.Buf = append(b.Buf, *rd...)
}

// Implementation of dns.Wirer
func (rd *RDATA) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	if *pos >= len(b) {
		*rd = RDATA{}
		if sniffer != nil {
			sniffer(nil, nil, dns.SniffRData, rd)
		}
		return
	}

	p0 := &b[*pos]
	n := len(b) - *pos
	*rd = b[*pos:]
	*pos += n
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRData, rd)
	}
	return
}

func (rd *RDATA) String() string {
	if n := len(*rd); n != 0 {
		return fmt.Sprintf("\\# %d %02x", len(*rd), *rd)
	}

	return "\\# 0"
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
	if *pos >= len(b) {
		return fmt.Errorf("(*rr.RR).Decode() - buffer underflow, len(b) %d(0x%x), pos %d(0x%x)", len(b), len(b), *pos, *pos)
	}

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
	case TYPE_CERT:
		rr.RData = &CERT{}
	case TYPE_CNAME:
		rr.RData = &CNAME{}
	case TYPE_DHCID:
		rr.RData = &DHCID{}
	case TYPE_DLV:
		rr.RData = &DLV{}
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
	case TYPE_HIP:
		rr.RData = &HIP{}
	case TYPE_IPSECKEY:
		rr.RData = &IPSECKEY{}
	case TYPE_ISDN:
		rr.RData = &ISDN{}
	case TYPE_KEY:
		rr.RData = &KEY{}
	case TYPE_KX:
		rr.RData = &KX{}
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
	case TYPE_NAPTR:
		rr.RData = &NAPTR{}
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
	case TYPE_NSEC:
		rr.RData = &NSEC{}
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
	case TYPE_SPF:
		rr.RData = &SPF{}
	case TYPE_SRV:
		rr.RData = &SRV{}
	case TYPE_SSHFP:
		rr.RData = &SSHFP{}
	case TYPE_TA:
		rr.RData = &TA{}
	case TYPE_TALINK:
		rr.RData = &TALINK{}
	case TYPE_TKEY:
		rr.RData = &TKEY{}
	case TYPE_TSIG:
		rr.RData = &TSIG{}
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

	if rdlength != 0 {
		if err = rr.RData.Decode(b[:*pos+int(rdlength)], pos, sniffer); err != nil {
			return
		}
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
	case *CERT:
		y := b.RData.(*CERT)
		return x.Type == y.Type &&
			x.KeyTag == y.KeyTag &&
			x.Algorithm == y.Algorithm &&
			bytes.Equal(x.Cert, y.Cert)
	case *CNAME:
		return strings.ToLower(x.Name) == strings.ToLower(b.RData.(*CNAME).Name)
	case *DHCID:
		y := b.RData.(*DHCID)
		return bytes.Equal(x.Data, y.Data)
	case *DLV:
		y := b.RData.(*DLV)
		return x.KeyTag == y.KeyTag &&
			x.Algorithm == y.Algorithm &&
			x.DigestType == y.DigestType &&
			bytes.Equal(x.Digest, y.Digest)
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
			x.Algorithm == y.Algorithm &&
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
	case *HIP:
		y := b.RData.(*HIP)
		if y.PKAlgorithm != y.PKAlgorithm ||
			!bytes.Equal(x.HIT, y.HIT) ||
			!bytes.Equal(x.PublicKey, y.PublicKey) ||
			len(x.RendezvousServers) != len(y.RendezvousServers) {
			return false
		}
		for i, v := range x.RendezvousServers {
			if strings.ToLower(v) != strings.ToLower(y.RendezvousServers[i]) {
				return false
			}
		}
		return true
	case *IPSECKEY:
		y := b.RData.(*IPSECKEY)
		if x.Precedence != y.Precedence ||
			x.GatewayType != y.GatewayType &&
				x.Algorithm != y.Algorithm {
			return false
		}

		switch x.GatewayType {
		default:
			return false
		case GatewayNone:
			return x.Gateway == nil && y.Gateway == nil
		case GatewayIPV4, GatewayIPV6:
			ipx, ok := x.Gateway.(net.IP)
			if !ok {
				return false
			}

			ipy, ok := y.Gateway.(net.IP)
			if !ok {
				return false
			}

			return ipx.Equal(ipy)
		case GatewayDomain:
			nx, ok := x.Gateway.(string)
			if !ok {
				return false
			}

			ny, ok := y.Gateway.(string)
			if !ok {
				return false
			}

			return nx == ny
		}
	case *ISDN:
		y := b.RData.(*ISDN)
		return x.ISDN == y.ISDN && x.Sa == y.Sa
	case *KEY:
		y := b.RData.(*KEY)
		return x.Flags == y.Flags &&
			x.Protocol == y.Protocol &&
			x.Algorithm == y.Algorithm &&
			bytes.Equal(x.Key, y.Key)
	case *KX:
		y := b.RData.(*KX)
		return x.Preference == y.Preference &&
			strings.ToLower(x.Exchanger) == strings.ToLower(y.Exchanger)
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
	case *NAPTR:
		y := b.RData.(*NAPTR)
		return x.Order == y.Order &&
			x.Preference == y.Preference &&
			x.Flags == y.Flags &&
			x.Services == y.Services &&
			x.Regexp == y.Regexp &&
			strings.ToLower(x.Replacement) == strings.ToLower(y.Replacement)
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
	case *NSEC:
		y := b.RData.(*NSEC)
		return x.NextDomainName == y.NextDomainName &&
			bytes.Equal(x.TypeBitMaps, y.TypeBitMaps)
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
	case *OPT:
		y := b.RData.(*OPT)
		if len(x.Values) != len(y.Values) {
			return false
		}
		for i, v := range x.Values {
			w := y.Values[i]
			if v.Code != w.Code {
				return false
			}

			if !bytes.Equal(v.Data, w.Data) {
				return false
			}
		}

		return true
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
			x.Algorithm == y.Algorithm &&
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
			x.Algorithm == y.Algorithm &&
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
	case *SPF:
		y := b.RData.(*SPF)
		if len(x.S) != len(y.S) {
			return false
		}
		for i, s := range x.S {
			if s != y.S[i] {
				return false
			}
		}

		return true
	case *SRV:
		y := b.RData.(*SRV)
		return x.Priority == y.Priority &&
			x.Weight == y.Weight &&
			x.Port == y.Port &&
			strings.ToLower(x.Target) == strings.ToLower(y.Target)
	case *SSHFP:
		y := b.RData.(*SSHFP)
		return x.Algorithm == y.Algorithm &&
			x.Type == y.Type &&
			bytes.Equal(x.Fingerprint, y.Fingerprint)
	case *TA:
		y := b.RData.(*TA)
		return x.KeyTag == y.KeyTag &&
			x.Algorithm == y.Algorithm &&
			x.DigestType == y.DigestType &&
			bytes.Equal(x.Digest, y.Digest)
	case *TALINK:
		y := b.RData.(*TALINK)
		return strings.ToLower(x.PrevName) == strings.ToLower(y.PrevName) &&
			strings.ToLower(x.NextName) == strings.ToLower(y.NextName)
	case *TKEY:
		y := b.RData.(*TKEY)
		return strings.ToLower(x.Algorithm) == strings.ToLower(y.Algorithm) &&
			x.Inception.Unix() == y.Inception.Unix() &&
			x.Expiration.Unix() == y.Expiration.Unix() &&
			x.Mode == y.Mode &&
			x.Error == y.Error &&
			bytes.Equal(x.KeyData, y.KeyData) &&
			bytes.Equal(x.OtherData, y.OtherData)
	case *TSIG:
		y := b.RData.(*TSIG)
		return strings.ToLower(x.AlgorithmName) == strings.ToLower(y.AlgorithmName) &&
			x.TimeSigned.Unix() == y.TimeSigned.Unix() &&
			x.Fudge == y.Fudge &&
			bytes.Equal(x.MAC, y.MAC) &&
			x.OriginalID == y.OriginalID &&
			x.Error == y.Error &&
			bytes.Equal(x.OtherData, y.OtherData)
	case *TXT:
		y := b.RData.(*TXT)
		if len(x.S) != len(y.S) {
			return false
		}
		for i, s := range x.S {
			if s != y.S[i] {
				return false
			}
		}

		return true
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
func (rd *RP) Encode(b *dns.Wirebuf) {
	(dns.DomainName)(rd.Mbox).Encode(b)
	(dns.DomainName)(rd.Txt).Encode(b)
}

// Implementation of dns.Wirer
func (rd *RP) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&rd.Mbox).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.DomainName)(&rd.Txt).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataRP, rd)
	}
	return
}

func (rd *RP) String() string {
	return fmt.Sprintf("%s %s", rd.Mbox, rd.Txt)
}

// RRSIG holds the zone RRSIG RData (RFC4034)
type RRSIG struct {
	// The Type Covered field identifies the type of the RRset that is covered 
	// by this RRSIG record.
	Type Type
	//  The Algorithm Number field identifies the cryptographic algorithm used
	// to create the signature. 
	Algorithm AlgorithmType
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
func (rd *RRSIG) Encode(b *dns.Wirebuf) {
	dns.Octets2(rd.Type).Encode(b)
	dns.Octet(rd.Algorithm).Encode(b)
	dns.Octet(rd.Labels).Encode(b)
	dns.Octets4(rd.TTL).Encode(b)
	dns.Octets4(rd.Expiration).Encode(b)
	dns.Octets4(rd.Inception).Encode(b)
	dns.Octets2(rd.KeyTag).Encode(b)
	b.DisableCompression()
	(*dns.DomainName)(&rd.Name).Encode(b)
	b.EnableCompression()
	b.Buf = append(b.Buf, rd.Signature...)
}

// Implementation of dns.Wirer
func (rd *RRSIG) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&rd.Type).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octet)(&rd.Algorithm).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octet)(&rd.Labels).Decode(b, pos, sniffer); err != nil {
		return
	}

	var ttl dns.Octets4
	if err = ttl.Decode(b, pos, sniffer); err != nil {
		return
	}

	rd.TTL = int32(ttl)

	if err = (*dns.Octets4)(&rd.Expiration).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octets4)(&rd.Inception).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octets2)(&rd.KeyTag).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.DomainName)(&rd.Name).Decode(b, pos, sniffer); err != nil {
		return
	}

	n := len(b) - *pos
	if n <= 0 {
		return fmt.Errorf("(*RRSIG).Decode: no signature data")
	}

	rd.Signature = make([]byte, n)
	copy(rd.Signature, b[*pos:])
	*pos += n
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataRRSIG, rd)
	}
	return
}

func (rd *RRSIG) String() string {
	return fmt.Sprintf("%s %d %d %d %s %s %d %s %s",
		rd.Type,
		rd.Algorithm,
		rd.Labels,
		rd.TTL,
		dns.Seconds2String(int64(rd.Expiration)),
		dns.Seconds2String(int64(rd.Inception)),
		rd.KeyTag,
		rd.Name,
		strutil.Base64Encode(rd.Signature),
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
func (rd *RT) Encode(b *dns.Wirebuf) {
	(dns.Octets2)(rd.Preference).Encode(b)
	(dns.DomainName)(rd.Hostname).Encode(b)
}

// Implementation of dns.Wirer
func (rd *RT) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&rd.Preference).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.DomainName)(&rd.Hostname).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataRT, rd)
	}
	return
}

func (rd *RT) String() string {
	return fmt.Sprintf("%d %s", rd.Preference, rd.Hostname)
}

// The SIG or "signature" resource record (RR) is the fundamental way that data
// is authenticated in the secure Domain Name System (DNS). As such it is the
// heart of the security provided.
type SIG struct {
	// The Type Covered field identifies the type of the RRset that is covered 
	// by this SIG record.
	Type Type
	//  The Algorithm Number field identifies the cryptographic algorithm used
	// to create the signature. 
	Algorithm AlgorithmType
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
func (rd *SIG) Encode(b *dns.Wirebuf) {
	dns.Octets2(rd.Type).Encode(b)
	dns.Octet(rd.Algorithm).Encode(b)
	dns.Octet(rd.Labels).Encode(b)
	dns.Octets4(rd.TTL).Encode(b)
	dns.Octets4(rd.Expiration).Encode(b)
	dns.Octets4(rd.Inception).Encode(b)
	dns.Octets2(rd.KeyTag).Encode(b)
	b.DisableCompression()
	(*dns.DomainName)(&rd.Name).Encode(b)
	b.EnableCompression()
	b.Buf = append(b.Buf, rd.Signature...)
}

// Implementation of dns.Wirer
func (rd *SIG) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&rd.Type).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octet)(&rd.Algorithm).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octet)(&rd.Labels).Decode(b, pos, sniffer); err != nil {
		return
	}

	var ttl dns.Octets4
	if err = ttl.Decode(b, pos, sniffer); err != nil {
		return
	}

	rd.TTL = int32(ttl)

	if err = (*dns.Octets4)(&rd.Expiration).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octets4)(&rd.Inception).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octets2)(&rd.KeyTag).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.DomainName)(&rd.Name).Decode(b, pos, sniffer); err != nil {
		return
	}

	n := len(b) - *pos
	if n <= 0 {
		return fmt.Errorf("(*SIG).Decode: no signature data")
	}

	rd.Signature = make([]byte, n)
	copy(rd.Signature, b[*pos:])
	*pos += n
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataSIG, rd)
	}
	return
}

func (rd *SIG) String() string {
	return fmt.Sprintf("%s %d %d %d %s %s %d %s %s",
		rd.Type,
		rd.Algorithm,
		rd.Labels,
		rd.TTL,
		dns.Seconds2String(int64(rd.Expiration)),
		dns.Seconds2String(int64(rd.Inception)),
		rd.KeyTag,
		rd.Name,
		strutil.Base64Encode(rd.Signature),
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
func (rd *SOA) Encode(b *dns.Wirebuf) {
	dns.DomainName(rd.MName).Encode(b)
	dns.DomainName(rd.RName).Encode(b)
	dns.Octets4(rd.Serial).Encode(b)
	dns.Octets4(rd.Refresh).Encode(b)
	dns.Octets4(rd.Retry).Encode(b)
	dns.Octets4(rd.Expire).Encode(b)
	dns.Octets4(rd.Minimum).Encode(b)
}

// Implementation of dns.Wirer
func (rd *SOA) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&rd.MName).Decode(b, pos, sniffer); err != nil {
		return
	}
	if err = (*dns.DomainName)(&rd.RName).Decode(b, pos, sniffer); err != nil {
		return
	}
	if (*dns.Octets4)(&rd.Serial).Decode(b, pos, sniffer); err != nil {
		return
	}
	if (*dns.Octets4)(&rd.Refresh).Decode(b, pos, sniffer); err != nil {
		return
	}
	if (*dns.Octets4)(&rd.Retry).Decode(b, pos, sniffer); err != nil {
		return
	}
	if (*dns.Octets4)(&rd.Expire).Decode(b, pos, sniffer); err != nil {
		return
	}
	if err = (*dns.Octets4)(&rd.Minimum).Decode(b, pos, sniffer); err != nil {
		return
	}
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataSOA, rd)
	}
	return
}

func (rd *SOA) String() string {
	return fmt.Sprintf("%s %s %d %d %d %d %d", rd.MName, rd.RName, rd.Serial, rd.Refresh, rd.Retry, rd.Expire, rd.Minimum)
}

// SPF represents SPF RR RDATA. The format of this type is identical to the TXT
// RR [RFC1035].  For either type, the character content of the record is
// encoded as [US-ASCII].
//
// It is recognized that the current practice (using a TXT record) is not
// optimal, but it is necessary because there are a number of DNS server and
// resolver implementations in common use that cannot handle the new RR type.
// The two-record-type scheme provides a forward path to the better solution of
// using an RR type reserved for this purpose.
//
// An SPF-compliant domain name SHOULD have SPF records of both RR types.  A
// compliant domain name MUST have a record of at least one type.  If a domain
// has records of both types, they MUST have identical content.  For example,
// instead of publishing just one record as in Section 3.1 above (RFC4408), it
// is better to publish:
//
//    example.com. IN TXT "v=spf1 +mx a:colo.example.com/28 -all"
//    example.com. IN SPF "v=spf1 +mx a:colo.example.com/28 -all"
//
// Example RRs in this document are shown with the TXT record type; however,
// they could be published with the SPF type or with both types.
type SPF struct {
	S []string
}

// Implementation of dns.Wirer
func (rd *SPF) Encode(b *dns.Wirebuf) {
	for _, s := range rd.S {
		dns.CharString(s).Encode(b)
	}
}

// Implementation of dns.Wirer
func (rd *SPF) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	s := []string{}
	for *pos < len(b) {
		var part dns.CharString
		if err = part.Decode(b, pos, sniffer); err != nil {
			return
		}

		s = append(s, string(part))
	}
	rd.S = s
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataSPF, rd)
	}
	return
}

func (rd *SPF) String() string {
	a := []string{}
	for _, s := range rd.S {
		a = append(a, fmt.Sprintf(`"%s"`, quote(s)))
	}
	return strings.Join(a, " ")
}

type SRV struct {
	// The priority of this target host.  A client MUST attempt to contact
	// the target host with the lowest-numbered priority it can reach;
	// target hosts with the same priority SHOULD be tried in an order
	// defined by the weight field.  The range is 0-65535.  This is a 16
	// bit unsigned integer in network byte order.
	Priority uint16
	// A server selection mechanism.  The weight field specifies a relative
	// weight for entries with the same priority. Larger weights SHOULD be
	// given a proportionately higher probability of being selected. The
	// range of this number is 0-65535.  This is a 16 bit unsigned integer
	// in network byte order.  Domain administrators SHOULD use Weight 0
	// when there isn't any server selection to do, to make the RR easier
	// to read for humans (less noisy).  In the presence of records
	// containing weights greater than 0, records with weight 0 should have
	// a very small chance of being selected.
	//
	// In the absence of a protocol whose specification calls for the use
	// of other weighting information, a client arranges the SRV RRs of the
	// same Priority in the order in which target hosts, specified by the
	// SRV RRs, will be contacted. The following algorithm SHOULD be used
	// to order the SRV RRs of the same priority:
	//
	// To select a target to be contacted next, arrange all SRV RRs (that
	// have not been ordered yet) in any order, except that all those with
	// weight 0 are placed at the beginning of the list.
	//
	// Compute the sum of the weights of those RRs, and with each RR
	// associate the running sum in the selected order. Then choose a
	// uniform random number between 0 and the sum computed (inclusive),
	// and select the RR whose running sum value is the first in the
	// selected order which is greater than or equal to the random number
	// selected.  The target host specified in the selected SRV RR is the
	// next one to be contacted by the client.  Remove this SRV RR from the
	// set of the unordered SRV RRs and apply the described algorithm to
	// the unordered SRV RRs to select the next target host.  Continue the
	// ordering process until there are no unordered SRV RRs.  This process
	// is repeated for each Priority.
	Weight uint16
	// The port on this target host of this service.  The range is 0-
	// 65535.  This is a 16 bit unsigned integer in network byte order.
	// This is often as specified in Assigned Numbers but need not be.
	Port uint16
	// The domain name of the target host.  There MUST be one or more
	// address records for this name, the name MUST NOT be an alias (in the
	// sense of RFC 1034 or RFC 2181).  Implementors are urged, but not
	// required, to return the address record(s) in the Additional Data
	// section.  Unless and until permitted by future standards action,
	// name compression is not to be used for this field.
	//
	// A Target of "." means that the service is decidedly not available at
	// this domain.
	Target string
}

// Implementation of dns.Wirer
func (rd *SRV) Encode(b *dns.Wirebuf) {
	dns.Octets2(rd.Priority).Encode(b)
	dns.Octets2(rd.Weight).Encode(b)
	dns.Octets2(rd.Port).Encode(b)
	dns.DomainName(rd.Target).Encode(b)
}

// Implementation of dns.Wirer
func (rd *SRV) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&rd.Priority).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octets2)(&rd.Weight).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octets2)(&rd.Port).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.DomainName)(&rd.Target).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataSRV, rd)
	}
	return
}

func (rd *SRV) String() string {
	return fmt.Sprintf("%d %d %d %s", rd.Priority, rd.Weight, rd.Port, rd.Target)
}

// SSHFPAlgorithm is the type of the SSHFP RData Algorithm field
type SSHFPAlgorithm byte

// Values of SSHFPAlgorithm
const (
	SSHFPAlgorithmReserved SSHFPAlgorithm = iota
	SSHFPAlgorithmRSA
	SSHFPAlgorithmDSA
)

// SSHFPType is the type of the SSHFP RData Type field
type SSHFPType byte

// Values of SSHFPType
const (
	SSHFPTypeReserved SSHFPType = iota
	SSHFPTypeSHA1
)

// SSHFP type represents RData of a SSHFP RR.  The SSHFP resource record (RR)
// is used to store a fingerprint of an    SSH public host key that is
// associated with a Domain Name System (DNS) name.
type SSHFP struct {
	// This algorithm number octet describes the algorithm of the public
	// key.  The following values are assigned:
	// 
	//           Value    Algorithm name
	//           -----    --------------
	//           0        reserved
	//           1        RSA
	//           2        DSS
	Algorithm SSHFPAlgorithm
	// The fingerprint type octet describes the message-digest algorithm
	// used to calculate the fingerprint of the public key.  The following
	// values are assigned:
	// 
	//           Value    Fingerprint type
	//           -----    ----------------
	//           0        reserved
	//           1        SHA-1
	Type SSHFPType
	// The fingerprint is calculated over the public key blob as described
	// in: Ylonen, T. and C. Lonvick, Ed., "The Secure Shell (SSH)
	// Transport Layer Protocol", RFC 4253, January 2006.
	// 
	// The message-digest algorithm is presumed to produce an opaque octet
	// string output, which is placed as-is in the RDATA fingerprint field.
	Fingerprint []byte
}

// Implementation of dns.Wirer
func (rd *SSHFP) Encode(b *dns.Wirebuf) {
	dns.Octet(rd.Algorithm).Encode(b)
	dns.Octet(rd.Type).Encode(b)
	b.Buf = append(b.Buf, rd.Fingerprint...)
}

// Implementation of dns.Wirer
func (rd *SSHFP) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octet)(&rd.Algorithm).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octet)(&rd.Type).Decode(b, pos, sniffer); err != nil {
		return
	}

	n := len(b) - *pos
	if n <= 0 {
		return fmt.Errorf("(*SSHFP).Decode: no fingerprint data")
	}

	rd.Fingerprint = make([]byte, n)
	copy(rd.Fingerprint, b[*pos:])
	*pos += n
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataSSHFP, rd)
	}
	return
}

func (rd *SSHFP) String() string {
	return fmt.Sprintf("%d %d %x",
		rd.Algorithm,
		rd.Type,
		rd.Fingerprint,
	)
}

/*
TA represent TA RR RDATA.

From: http://tools.ietf.org/html/draft-lewis-dns-undocumented-types-01

 2.10 TA (32768)

 TA stands for "Trust Anchor" and, as far as can be determined, not defined in
 an IETF document.  (The ATMA record is also not mentioned in an IETF
 document.)  The record is described in a document named INI1999-19.pdf on the
 www.watson.org web site.

 In that document, the RDATA is described as

 "The fields in the TA record contain exactly the same data as the DS record
 and use the same IANA-assigned values in the algorithm and digest type fields
 as the DS record."

 The following appears on the IANA webpage for DNS Parameters:

 Deploying DNSSEC Without a Signed Rott[sic].  TR 1999-19,
  Information Networking Institute, Carnegie Mellon U, April 2004.
  http://cameo.library.cmu.edu/
  http://www.watson.org/~weiler/INI1999-19.pdf

 The DS record is defined in RFC4034.
*/
type TA struct {
	// The key tag is calculated as specified in RFC 2535
	KeyTag uint16
	// Algorithm MUST be allowed to sign DNS data
	Algorithm AlgorithmType
	// The digest type is an identifier for the digest algorithm used
	DigestType HashAlgorithm
	// The digest is calculated over the
	// canonical name of the delegated domain name followed by the whole
	// RDATA of the KEY record (all four fields)
	Digest []byte
}

// Implementation of dns.Wirer
func (rd *TA) Encode(b *dns.Wirebuf) {
	dns.Octets2(rd.KeyTag).Encode(b)
	dns.Octet(rd.Algorithm).Encode(b)
	dns.Octet(rd.DigestType).Encode(b)
	b.Buf = append(b.Buf, rd.Digest...)
}

// Implementation of dns.Wirer
func (rd *TA) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(&rd.KeyTag).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octet)(&rd.Algorithm).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octet)(&rd.DigestType).Decode(b, pos, sniffer); err != nil {
		return
	}

	var n int
	switch rd.DigestType {
	case HashAlgorithmSHA1:
		n = 20
	default:
		return fmt.Errorf("unsupported digest type %d", rd.DigestType)
	}

	end := *pos + n
	if end > len(b) {
		return fmt.Errorf("(*rr.TA).Decode() - buffer underflow")
	}

	rd.Digest = append([]byte{}, b[*pos:end]...)
	*pos = end
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataTA, rd)
	}
	return
}

func (rd *TA) String() string {
	if asserts && len(rd.Digest) == 0 {
		panic("internal error")
	}

	return fmt.Sprintf("%d %d %d %s", rd.KeyTag, rd.Algorithm, rd.DigestType, hex.EncodeToString(rd.Digest))
}

/*
TALINK represent TALINK RR RDATA.

From: http://tools.ietf.org/html/draft-lewis-dns-undocumented-types-01

 2.6 TALINK (58)

 TALINK stands for Trust Anchor Link and is last defined in the draft
 named draft-wijngaards-dnsop-trust-history-02, available on the
 tools.ietf.org site.

 The RDATA section is defined as two fully qualified domain names that
 are not subject to message compression nor DNSSEC downcasing.

 The draft expired in February 2010.

*/
type TALINK struct {
	PrevName string
	NextName string
}

// Implementation of dns.Wirer
func (rd *TALINK) Encode(b *dns.Wirebuf) {
	b.DisableCompression()
	dns.DomainName(rd.PrevName).Encode(b)
	dns.DomainName(rd.NextName).Encode(b)
	b.EnableCompression()
}

// Implementation of dns.Wirer
func (rd *TALINK) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&rd.PrevName).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.DomainName)(&rd.NextName).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataTALINK, rd)
	}
	return
}

func (rd *TALINK) String() string {
	return fmt.Sprintf("%s %s", rd.PrevName, rd.NextName)
}

// TKEYMode type is the type of the TKEY Mode field.
type TKEYMode uint16

func (m TKEYMode) String() (s string) {
	if s = TKEYModes[m]; s != "" {
		return
	}

	return fmt.Sprintf("TKEYMode%d", m)
}

//Values of TKEYMode
const (
	// RFC2930/2.5
	//         Value    Description
	//         -----    -----------
	//          0        - reserved, see section 7
	//          1       server assignment
	//          2       Diffie-Hellman exchange
	//          3       GSS-API negotiation
	//          4       resolver assignment
	//          5       key deletion
	//         6-65534   - available, see section 7
	//         65535     - reserved, see section 7

	TKEYModeReserved0 TKEYMode = iota
	TKEYModeServerAssignment
	TKEYModeDiffieHellmanExchange
	TKEYModeGSSAPINegotation
	TKEYModeResolverAssignment
	TKEYModeKeyDeletion
	TKEYModeReserved65535 TKEYMode = 65535
)

var TKEYModes = map[TKEYMode]string{
	TKEYModeReserved0:             "Reserved0",
	TKEYModeServerAssignment:      "ServerAssignment",
	TKEYModeDiffieHellmanExchange: "DiffieHellmanExchange",
	TKEYModeGSSAPINegotation:      "GSSAPINegotation",
	TKEYModeResolverAssignment:    "ResolverAssignment",
	TKEYModeKeyDeletion:           "KeyDeletion",
	TKEYModeReserved65535:         "Reserved65535",
}

// TKEY represents TKEY RR RDATA [RFC2930]. TKEY RR can be used in a number of
// different modes to establish and delete such shared secret keys between a
// DNS resolver and server. 
type TKEY struct {
	// The algorithm name is in the form of a domain name with the same
	// meaning as in [RFC 2845].  The algorithm determines how the secret
	// keying material agreed to using the TKEY RR is actually used to
	// derive the algorithm specific key.
	Algorithm string
	// The inception time and expiration times are in number of seconds
	// since the beginning of 1 January 1970 GMT ignoring leap seconds
	// treated as modulo 2**32 using ring arithmetic [RFC 1982]. In
	// messages between a DNS resolver and a DNS server where these fields
	// are meaningful, they are either the requested validity interval for
	// the keying material asked for or specify the validity interval of
	// keying material provided.
	//
	// To avoid different interpretations of the inception and expiration
	// times in TKEY RRs, resolvers and servers exchanging them must have
	// the same idea of what time it is.  One way of doing this is with the
	// NTP protocol [RFC 2030] but that or any other time synchronization
	// used for this purpose MUST be done securely.
	Inception  time.Time
	Expiration time.Time
	// The mode field specifies the general scheme for key agreement or the
	// purpose of the TKEY DNS message.  Servers and resolvers supporting
	// this specification MUST implement the Diffie-Hellman key agreement
	// mode and the key deletion mode for queries.  All other modes are
	// OPTIONAL.  A server supporting TKEY that receives a TKEY request
	// with a mode it does not support returns the BADMODE error.
	Mode TKEYMode
	// The error code field is an extended RCODE.
	Error TSIGRCODE
	// The meaning of this data depends on the mode.
	KeyData []byte
	// The Other Data field is not used in this specification but may be
	// used in future extensions.
	OtherData []byte
}

// Implementation of dns.Wirer
func (rd *TKEY) Encode(b *dns.Wirebuf) {
	//BUG Supports times only up to 2106-02-07 06:28:15 +0000 UTC
	dns.DomainName(rd.Algorithm).Encode(b)
	dns.Octets4(rd.Inception.UTC().Unix()).Encode(b)
	dns.Octets4(rd.Expiration.UTC().Unix()).Encode(b)
	dns.Octets2(rd.Mode).Encode(b)
	dns.Octets2(rd.Error).Encode(b)
	dns.Octets2(len(rd.KeyData)).Encode(b)
	b.Buf = append(b.Buf, rd.KeyData...)
	dns.Octets2(len(rd.OtherData)).Encode(b)
	b.Buf = append(b.Buf, rd.OtherData...)
}

// Implementation of dns.Wirer
func (rd *TKEY) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	//BUG Supports times only up to 2106-02-07 06:28:15 +0000 UTC
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&rd.Algorithm).Decode(b, pos, sniffer); err != nil {
		return
	}

	var u32 dns.Octets4
	if err = u32.Decode(b, pos, sniffer); err != nil {
		return
	}

	rd.Inception = time.Unix(int64(u32), 0)

	if err = u32.Decode(b, pos, sniffer); err != nil {
		return
	}

	rd.Expiration = time.Unix(int64(u32), 0)

	if err = (*dns.Octets2)(&rd.Mode).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octets2)(&rd.Error).Decode(b, pos, sniffer); err != nil {
		return
	}

	var u16 dns.Octets2
	if err = u16.Decode(b, pos, sniffer); err != nil {
		return
	}

	n := int(u16)
	if *pos+n > len(b)+1 {
		return fmt.Errorf("(*rr.TKEY).Decode() - buffer underflow")
	}

	rd.KeyData = make([]byte, n)
	copy(rd.KeyData, b[*pos:])
	*pos += n

	if err = u16.Decode(b, pos, sniffer); err != nil {
		return
	}

	n = int(u16)
	if *pos+n > len(b)+1 {
		return fmt.Errorf("(*rr.TKEY).Decode() - buffer underflow")
	}

	rd.OtherData = make([]byte, n)
	copy(rd.OtherData, b[*pos:])
	*pos += n

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataTKEY, rd)
	}
	return
}

func (rd *TKEY) String() string {
	return fmt.Sprintf(
		"%s %s %s %s %s %x %x",
		rd.Algorithm,
		time.Unix(rd.Inception.UTC().Unix(), 0),
		time.Unix(rd.Expiration.UTC().Unix(), 0),
		rd.Mode,
		rd.Error,
		rd.KeyData,
		rd.OtherData,
	)
}

// TSIGRCODE is the type of the TKEY/TSIG Error field. Values of TSIGRCODE <= 15
// have the same meaning as the same numbered values of msg.RCODE.
type TSIGRCODE uint16

func (t TSIGRCODE) String() (s string) {
	if s = TSIGRCODEs[t]; s != "" {
		return
	}

	return fmt.Sprintf("TSIGRCODE%d", t)
}

// Values of TSIGRCODE
const (
	TSIG_BADSIG TSIGRCODE = iota + 16
	TSIG_BADKEY
	TSIG_BADTIME
	TKEY_BADMODE
	TKEY_BADNAME
	TKEY_BADLAG
)

// Text values of TSIGRCODE
var TSIGRCODEs = map[TSIGRCODE]string{
	// 0               No error condition
	0: "RC_NO_ERROR RCODE",
	// 1               Format error - The name server was
	//                 unable to interpret the query.
	1: "RC_FORMAT_ERROR",
	// 2               Server failure - The name server was
	//                 unable to process this query due to a
	//                 problem with the name server.
	2: "RC_SERVER_FAILURE",
	// 3               Name Error - Meaningful only for
	//                 responses from an authoritative name
	//                 server, this code signifies that the
	//                 domain name referenced in the query does
	//                 not exist.
	3: "RC_NAME_ERROR",
	// 4               Not Implemented - The name server does
	//                 not support the requested kind of query.
	4: "RC_NOT_IMPLEMENETD",
	// 5               Refused - The name server refuses to
	//                 perform the specified operation for
	//                 policy reasons.  For example, a name
	//                 server may not wish to provide the
	//                 information to the particular requester,
	//                 or a name server may not wish to perform
	//                 a particular operation (e.g., zone
	//                 transfer) for particular data.
	5: "RC_REFUSED",
	// 6-15            Reserved for future use.
	TSIG_BADSIG:  "BADSIG",
	TSIG_BADKEY:  "BADKEY",
	TSIG_BADTIME: "BADTIME",
	TKEY_BADMODE: "BADMODE",
	TKEY_BADNAME: "BADNAME",
	TKEY_BADLAG:  "BADALG",
}

// TSIG represents TSIG RR RDATA. TSIG RRs are dynamically computed to cover a
// particular DNS transaction and are not DNS RRs in the usual sense.
type TSIG struct {
	AlgorithmName string // Name of the algorithm in domain name syntax.
	TimeSigned    time.Time
	Fudge         time.Duration // Permitted error in TimeSigned
	MAC           []byte        // Defined by Algorithm Name.
	OriginalID    uint16        // Original message ID.
	Error         TSIGRCODE     // Expanded RCODE covering TSIG processing.
	OtherData     []byte        // Empty unless Error == BADTIME.
}

// Implementation of dns.Wirer
func (rd *TSIG) Encode(b *dns.Wirebuf) {
	dns.DomainName(rd.AlgorithmName).Encode(b)
	secs := rd.TimeSigned.UTC().Unix()
	for i := 0; i < 6; i++ {
		dns.Octet(secs >> 40).Encode(b)
		secs <<= 8
	}
	dns.Octets2(rd.Fudge / time.Second).Encode(b)
	dns.Octets2(len(rd.MAC)).Encode(b)
	b.Buf = append(b.Buf, rd.MAC...)
	dns.Octets2(rd.OriginalID).Encode(b)
	dns.Octets2(rd.Error).Encode(b)
	dns.Octets2(len(rd.OtherData)).Encode(b)
	b.Buf = append(b.Buf, rd.OtherData...)
}

// Implementation of dns.Wirer
func (rd *TSIG) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.DomainName)(&rd.AlgorithmName).Decode(b, pos, sniffer); err != nil {
		return
	}

	var ts int64
	var bt dns.Octet
	for i := 0; i < 6; i++ {
		if err = bt.Decode(b, pos, sniffer); err != nil {
			return
		}

		ts = ts<<8 | int64(bt)
	}
	rd.TimeSigned = time.Unix(ts, 0)

	var u16 dns.Octets2
	if err = u16.Decode(b, pos, sniffer); err != nil {
		return
	}

	rd.Fudge = time.Duration(u16) * time.Second

	if err = u16.Decode(b, pos, sniffer); err != nil {
		return
	}

	n := int(u16)
	if *pos+n > len(b)+1 {
		return fmt.Errorf("(*rr.TSIG).Decode() - buffer underflow")
	}

	rd.MAC = make([]byte, n)
	copy(rd.MAC, b[*pos:])
	*pos += n

	if err = u16.Decode(b, pos, sniffer); err != nil {
		return
	}

	rd.OriginalID = uint16(u16)

	if err = u16.Decode(b, pos, sniffer); err != nil {
		return
	}

	rd.Error = TSIGRCODE(u16)

	if err = u16.Decode(b, pos, sniffer); err != nil {
		return
	}

	n = int(u16)
	if *pos+n > len(b)+1 {
		return fmt.Errorf("(*rr.TSIG).Decode() - buffer underflow")
	}

	rd.OtherData = make([]byte, n)
	copy(rd.OtherData, b[*pos:])
	*pos += n

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataTSIG, rd)
	}
	return
}

func (rd *TSIG) String() string {
	return fmt.Sprintf(
		"%s %s %s %x %d %s %x",
		rd.AlgorithmName,
		time.Unix(rd.TimeSigned.UTC().Unix(), 0),
		rd.Fudge,
		rd.MAC,
		rd.OriginalID,
		rd.Error,
		rd.OtherData,
	)
}

// TXT holds the TXT RData
type TXT struct {
	S []string
}

// Implementation of dns.Wirer
func (rd *TXT) Encode(b *dns.Wirebuf) {
	for _, s := range rd.S {
		dns.CharString(s).Encode(b)
	}
}

// Implementation of dns.Wirer
func (rd *TXT) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	s := []string{}
	for *pos < len(b) {
		var part dns.CharString
		if err = part.Decode(b, pos, sniffer); err != nil {
			return
		}

		s = append(s, string(part))
	}
	rd.S = s
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataTXT, rd)
	}
	return
}

func (rd *TXT) String() string {
	a := []string{}
	for _, s := range rd.S {
		a = append(a, fmt.Sprintf(`"%s"`, quote(s)))
	}
	return strings.Join(a, " ")
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
func (rd *WKS) Encode(b *dns.Wirebuf) {
	ip4(rd.Address).Encode(b)
	dns.Octet(rd.Protocol).Encode(b)
	bits := make([]byte, 0, 1024/8)
	for k := range rd.Ports {
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
func (rd *WKS) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*ip4)(&rd.Address).Decode(b, pos, sniffer); err != nil {
		return
	}

	if err = (*dns.Octet)(&rd.Protocol).Decode(b, pos, sniffer); err != nil {
		return
	}

	rd.Ports = map[IP_Port]struct{}{}
	n := len(b) - *pos
	if n == 0 {
		if sniffer != nil {
			sniffer(p0, &b[*pos-1], dns.SniffRDataWKS, rd)
		}
		return
	}

	b = b[*pos:]
	for i, v := range b {
		for bit := 0; v != 0; bit, v = bit+1, v>>1 {
			if v&1 != 0 {
				rd.Ports[IP_Port(i<<3+bit)] = struct{}{}
			}
		}
	}
	*pos += n
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataWKS, rd)
	}
	return
}

func (rd *WKS) String() string {
	buf := &bytes.Buffer{}
	buf.WriteString(rd.Address.String())
	buf.WriteString(" ")
	proto := IP_Protocols[rd.Protocol]
	if proto == "" {
		proto = strconv.Itoa(int(rd.Protocol))
	}
	buf.WriteString(proto)
	for k := range rd.Ports {
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

// Type codes. Types marked with * next to reference are not supported.
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
	TYPE_EID        // 31 Endpoint Identifier                         [Patton]*
	TYPE_NIMLOC     // 32 Nimrod Locator                              [Patton]*
	TYPE_SRV        // 33 Server Selection                            [RFC2782]
	TYPE_ATMA       // 34 ATM Address                                 [ATMDOC]*
	TYPE_NAPTR      // 35 Naming Authority Pointer                    [RFC2915][RFC2168][RFC3403]
	TYPE_KX         // 36 Key Exchanger                               [RFC2230]
	TYPE_CERT       // 37 CERT                                        [RFC4398]
	TYPE_A6         // 38 A6 (Experimental)                           [RFC3226][RFC2874]*
	TYPE_DNAME      // 39 DNAME                                       [RFC2672]
	TYPE_SINK       // 40 SINK                                        [Eastlake]*
	TYPE_OPT        // 41 OPT                                         [RFC2671]
	TYPE_APL        // 42 APL (Experimental)                          [RFC3123]*
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
	TYPE_NINFO  // 56 NINFO                                       [Reid]*
	TYPE_RKEY   // 57 RKEY                                        [Reid]*
	TYPE_TALINK // 58 Trust Anchor LINK                           [Wijngaards]*
	TYPE_CDS    // 59 Child DS                                    [Barwood]*
)

const (
	_ Type = iota + 98

	TYPE_SPF    //  99                                             [RFC4408]
	TYPE_UINFO  // 100                                             [IANA-Reserved]*
	TYPE_UID    // 101                                             [IANA-Reserved]*
	TYPE_GID    // 102                                             [IANA-Reserved]*
	TYPE_UNSPEC // 103                                             [IANA-Reserved]*
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

	TYPE_URI // 256 URI                                        [Faltstrom]*
	TYPE_CAA // 257 Certification Authority Authorization      [Hallam-Baker]*
)

const (
	_ Type = iota + 0x7FFF

	TYPE_TA  // 32768   DNSSEC Trust Authorities               [Weiler]*
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

func (t Type) String() (s string) {
	var ok bool
	if s, ok = Types[t]; !ok {
		return fmt.Sprintf("TYPE%d", uint16(t))
	}
	return
}

// Implementation of dns.Wirer
func (t Type) Encode(b *dns.Wirebuf) {
	dns.Octets2(t).Encode(b)
}

// Implementation of dns.Wirer
func (t *Type) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.Octets2)(t).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffType, *t)
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
func (rd *X25) Encode(b *dns.Wirebuf) {
	(dns.CharString)(rd.PSDN).Encode(b)
}

// Implementation of dns.Wirer
func (rd *X25) Decode(b []byte, pos *int, sniffer dns.WireDecodeSniffer) (err error) {
	p0 := &b[*pos]
	if err = (*dns.CharString)(&rd.PSDN).Decode(b, pos, sniffer); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(p0, &b[*pos-1], dns.SniffRDataX25, rd)
	}
	return
}

func (rd *X25) String() string {
	return fmt.Sprintf(`"%s"`, quote(rd.PSDN))
}
