// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

package dns

import (
	"fmt"
	"strings"
)

// CharString is a DNS <character-string> (RFC 1035) implementing Wirer.
type CharString string

// Implementation of Wirer
func (s CharString) Encode(b *Wirebuf) {
	n := len(s)
	if n > 255 {
		panic(fmt.Errorf("can't encode <character-string> %q, len > 255", s))
	}

	Octet(n).Encode(b)
	b.Buf = append(b.Buf, []byte(string(s))...)
}

// Implementation of Wirer
func (s *CharString) Decode(b []byte, pos *int, sniffer WireDecodeSniffer) (err error) {
	p := *pos
	if p >= len(b) {
		return fmt.Errorf("CharString.Decode() - buffer underflow")
	}

	p0 := &b[*pos]
	n := int(b[p])
	*pos += 1
	if p+n >= len(b) {
		return fmt.Errorf("CharString.Decode() - buffer underflow")

	}
	*s = CharString(b[p+1 : p+n+1])
	*pos += n
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], SniffCharString, *s)
	}
	return
}

// Quoted returns s with `"` escaped as `\"`
func (s CharString) Quoted() string {
	return strings.Replace(string(s), `"`, `\"`, -1)
}

// DomainName is a DNS <domain-name> (RFC 1035) implementing Wirer.
type DomainName string

// Implementation of Wirer
func (s DomainName) Encode(b *Wirebuf) {
	name := RootedName(string(s))
	labels, err := Labels(name)
	if err != nil {
		panic(err)
	}

	for _, label := range labels {
		if b.zip >= 0 && label != "" {
			if pos, ok := b.names[name]; ok { // RFC 1034/4.1.4. Message compression
				Octets2(0xC000 | pos).Encode(b)
				return
			}
		}

		pos := len(b.Buf)
		if name != "" && pos < 0x4000 {
			b.names[name] = pos
			name = name[len(label)+1:]
		}
		CharString(label).Encode(b)
	}
}

func (s *DomainName) decode(b []byte, pos *int) (err error) {
	labels := []string{}
	label := CharString("")
	for {
		if *pos >= len(b) {
			return fmt.Errorf("DomainName.Decode() - buffer underflow")
		}

		if b[*pos]&0xC0 == 0xC0 { // compressed
			var ptr Octets2
			if err = ptr.Decode(b, pos, nil); err != nil {
				return
			}

			p := int(ptr) ^ 0xC000
			var name DomainName
			if err = name.decode(b, &p); err != nil {
				return
			}

			labels = append(labels, string(name))
			*s = DomainName(strings.Join(labels, "."))
			return
		}

		if err = label.Decode(b, pos, nil); err != nil {
			return
		}

		labels = append(labels, string(label))
		if label == "" {
			if len(labels) != 1 {
				*s = DomainName(strings.Join(labels, "."))
			} else {
				*s = "."
			}
			return
		}

	}
	panic("unreachable")
}

// Implementation of Wirer
func (s *DomainName) Decode(b []byte, pos *int, sniffer WireDecodeSniffer) (err error) {
	ip0 := *pos
	if err = s.decode(b, pos); err != nil {
		return
	}

	if sniffer != nil {
		sniffer(&b[ip0], &b[*pos-1], SniffDomainName, *s)
	}
	return
}

// Octet is a byte implementing Wirer.
type Octet byte

// Implementation of Wirer
func (o Octet) Encode(b *Wirebuf) {
	b.Buf = append(b.Buf, byte(o))
}

// Implementation of Wirer
func (o *Octet) Decode(b []byte, pos *int, sniffer WireDecodeSniffer) (err error) {
	p := *pos
	if p+1 > len(b) {
		return fmt.Errorf("Octet.Decode() - buffer underflow")
	}
	p0 := &b[*pos]
	*o = Octet(b[p])
	*pos += 1
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], SniffOctet, *o)
	}
	return
}

// Octets2 is an uint16 implementing Wirer.
type Octets2 uint16

// Implementation of Wirer
func (n Octets2) Encode(b *Wirebuf) {
	b.Buf = append(b.Buf, byte(n>>8), byte(n))
}

// Implementation of Wirer
func (n *Octets2) Decode(b []byte, pos *int, sniffer WireDecodeSniffer) (err error) {
	p := *pos
	if p+2 > len(b) {
		return fmt.Errorf("Octets2.Decode() - buffer underflow")
	}
	p0 := &b[*pos]
	*n = Octets2(b[p])<<8 + Octets2(b[p+1])
	*pos = p + 2
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], SniffOctets2, *n)
	}
	return
}

// Octets4 is an uint32 implementing Wirer.
type Octets4 uint32

// Implementation of Wirer
func (n Octets4) Encode(b *Wirebuf) {
	b.Buf = append(b.Buf, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// Implementation of Wirer
func (n *Octets4) Decode(b []byte, pos *int, sniffer WireDecodeSniffer) (err error) {
	p := *pos
	if p+4 > len(b) {
		return fmt.Errorf("Octets4.Decode() - buffer underflow")
	}
	p0 := &b[*pos]
	*n = Octets4(b[p])<<24 + Octets4(b[p+1])<<16 + Octets4(b[p+2])<<8 + Octets4(b[p+3])
	*pos = p + 4
	if sniffer != nil {
		sniffer(p0, &b[*pos-1], SniffOctets4, *n)
	}
	return
}

// Wirebuf holds data for encoding DNS messages.
type Wirebuf struct {
	Buf   []byte         // The encoding buffer
	names map[string]int // Offsets of names already in Buf for compressing (RFC 1035/4.1.4.)
	zip   int
}

// NewWirebuf returns a newly created Wirebuf ready for use.
// Compression is enabled by default.
func NewWirebuf() *Wirebuf {
	return &Wirebuf{nil, map[string]int{}, 0}
}

// EnableCompression increments enable of <domain-name> compression (RFC
// 1034/4.1.4)
func (w *Wirebuf) EnableCompression() {
	w.zip++
}

// DisableCompression decrements enable of <domain-name> compression (RFC
// 1034/4.1.4)
func (w *Wirebuf) DisableCompression() {
	w.zip--
}

// WireDecodeSniffed tags data passed to WireDecodeSniffer
type WireDecodeSniffed int

// Values of WireDecodeSniffed
const (
	_                    WireDecodeSniffed = iota
	SniffCharString                        // A domain name label
	SniffClass                             // A CLASS
	SniffDomainName                        // A domain name
	SniffEXT_RCODE                         // An EXT_RCODE
	SniffHeader                            // A DNS message header
	SniffIPV4                              // An IP V4 address
	SniffIPV6                              // An IP V6 address
	SniffMessage                           // A DNS message
	SniffOPT_DATA                          // OPT resource record attr/value pair
	SniffOctet                             // An octet
	SniffOctets2                           // Two octets
	SniffOctets4                           // Four octets
	SniffQuestion                          // A DNS message question
	SniffQuestionItem                      // A DNS message question item
	SniffRData                             // Resource record data
	SniffRDataA                            // A resource record data
	SniffRDataAAAA                         // AAAA resource record data
	SniffRDataAFSDB                        // AFSDB resource record data
	SniffRDataCERT                         // CERT resource record data
	SniffRDataCNAME                        // CNAME resource record data
	SniffRDataDHCID                        // DHCID resource record data
	SniffRDataDLV                          // DLV resource record data
	SniffRDataDNAME                        // DNAME resource record data
	SniffRDataDNSKEY                       // DNSKEY resource record data
	SniffRDataDS                           // DS resource record data
	SniffRDataGPOS                         // GPOS resource record data
	SniffRDataHINFO                        // HINFO resource record data
	SniffRDataHIP                          // HIP resource record data
	SniffRDataIPSECKEY                     // IPSECKEY resource record data
	SniffRDataISDN                         // ISDN resource record data
	SniffRDataKEY                          // KEY resource record data
	SniffRDataKX                           // KX resource record data
	SniffRDataLOC                          // LOC resource record data
	SniffRDataMB                           // MB resource record data
	SniffRDataMD                           // MD resource record data
	SniffRDataMF                           // MF resource record data
	SniffRDataMG                           // MG resource record data
	SniffRDataMINFO                        // MINFO resource record data
	SniffRDataMR                           // MR resource record data
	SniffRDataMX                           // MX resource record data
	SniffRDataNAPTR                        // NAPTR pseudo resource record data
	SniffRDataNODATA                       // NODATA pseudo resource record data
	SniffRDataNS                           // NS resource record data
	SniffRDataNSAP                         // NSAP resource record data
	SniffRDataNSAP_PTR                     // NSAP-PTR resource record data
	SniffRDataNSEC                         // NSEC resource record data
	SniffRDataNSEC3                        // NSEC3 resource record data
	SniffRDataNSEC3PARAM                   // NSEC3PARAM resource record data
	SniffRDataNULL                         // NULL resource record data
	SniffRDataOPT                          // OPT resource record data
	SniffRDataPTR                          // PTR resource record data
	SniffRDataPX                           // PX resource record data
	SniffRDataRT                           // RT resource record data
	SniffRDataRP                           // RP resource record data
	SniffRDataRRSIG                        // RRSIG resource record data
	SniffRDataSIG                          // SIG resource record data
	SniffRDataSOA                          // SOA resource record data
	SniffRDataSPF                          // SPF resource record data
	SniffRDataSRV                          // SRV resource record data
	SniffRDataSSHFP                        // SSHFP resource record data
	SniffRDataTA                           // TA resource record data
	SniffRDataTALINK                       // TALINK resource record data
	SniffRDataTKEY                         // TKEY resource record data
	SniffRDataTLSA                         // TLSA resource record data
	SniffRDataTSIG                         // TSIG resource record data
	SniffRDataTXT                          // TXT resource record data
	SniffRDataURI                          // URI resource record data
	SniffRDataWKS                          // WKS resource record data
	SniffRDataX25                          // X25 resource record data
	SniffRR                                // Any or unknown/unsupported type resource record
	SniffType                              // A TYPE
) //TODO +test

// WireDecodeSniffer is the type of the hook called by Wirer.Decode.  p0 points
// to a wire buffer on entry to Decode, p to the last byte of the buffer used
// on leaving the same.  tag describes what was pulled from the wire buffer and
// info may optionally carry the just decoded entity (or a pointer to the same
// when more ćonvenient).
type WireDecodeSniffer func(p0, p *byte, tag WireDecodeSniffed, info interface{})

// Wirer is a DNS wire format encoder/decoder.
type Wirer interface {
	// Encode appends data in DNS wire format to Wirebuf.Buf.
	// If the buffer has not enough free space available it will be reallocated.
	Encode(*Wirebuf)
	// Decode decodes data from a DNS wire format in b, starting at p.
	// Decode may return a non nil Error if b is not in the correct format.
	// After Decode, p is adjusted to reflect the amount of data consumed from b.
	// If sniffer is not nil it is invoked with a description of the decoded stuff.
	Decode(b []byte, p *int, sniffer WireDecodeSniffer) error
}
