// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz


package dns

import (
	"fmt"
	"os"
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
func (s *CharString) Decode(b []byte, pos *int) (err os.Error) {
	p := *pos
	if p >= len(b) {
		return fmt.Errorf("CharString.Decode() - buffer underflow")
	}

	n := int(b[p])
	*pos += 1
	if p+n >= len(b) {
		return fmt.Errorf("CharString.Decode() - buffer underflow")

	}
	*s = CharString(b[p+1 : p+n+1])
	*pos += n
	return
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

// Implementation of Wirer
func (s *DomainName) Decode(b []byte, pos *int) (err os.Error) {
	labels := []string{}
	label := CharString("")
	for {
		if *pos >= len(b) {
			return fmt.Errorf("DomainName.Decode() - buffer underflow")
		}

		if b[*pos]&0xC0 == 0xC0 { // compressed
			var ptr Octets2
			if err = ptr.Decode(b, pos); err != nil {
				return
			}

			p := int(ptr) ^ 0xC000
			var name DomainName
			if err = name.Decode(b, &p); err != nil {
				return
			}

			labels = append(labels, string(name))
			*s = DomainName(strings.Join(labels, "."))
			return
		}

		if err = label.Decode(b, pos); err != nil {
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

// Octet is a byte implementing Wirer.
type Octet byte

// Implementation of Wirer
func (o Octet) Encode(b *Wirebuf) {
	b.Buf = append(b.Buf, byte(o))
}

// Implementation of Wirer
func (o *Octet) Decode(b []byte, pos *int) (err os.Error) {
	p := *pos
	if p+1 > len(b) {
		return fmt.Errorf("Octet.Decode() - buffer underflow")
	}
	*o = Octet(b[p])
	*pos += 1
	return
}

// Octets2 is an uint16 implementing Wirer.
type Octets2 uint16

// Implementation of Wirer
func (n Octets2) Encode(b *Wirebuf) {
	b.Buf = append(b.Buf, byte(n>>8), byte(n))
}

// Implementation of Wirer
func (n *Octets2) Decode(b []byte, pos *int) (err os.Error) {
	p := *pos
	if p+2 > len(b) {
		return fmt.Errorf("Octets2.Decode() - buffer underflow")
	}
	*n = Octets2(b[p])<<8 + Octets2(b[p+1])
	*pos = p + 2
	return
}

// Octets4 is an uint32 implementing Wirer.
type Octets4 uint32

// Implementation of Wirer
func (n Octets4) Encode(b *Wirebuf) {
	b.Buf = append(b.Buf, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// Implementation of Wirer
func (n *Octets4) Decode(b []byte, pos *int) (err os.Error) {
	p := *pos
	if p+4 > len(b) {
		return fmt.Errorf("Octets4.Decode() - buffer underflow")
	}
	*n = Octets4(b[p])<<24 + Octets4(b[p+1])<<16 + Octets4(b[p+2])<<8 + Octets4(b[p+3])
	*pos = p + 4
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

// EnableCompression increments enable of <domain-name> compression (RFC 1034/4.1.4)
func (w *Wirebuf) EnableCompression() {
	w.zip++
}

// DisableCompression decrements enable of <domain-name> compression (RFC 1034/4.1.4)
func (w *Wirebuf) DisableCompression() {
	w.zip--
}

// Wirer is a DNS wire format encoder/decoder.
type Wirer interface {
	// Encode appends data in DNS wire format to Wirebuf.Buf.
	// If the buffer has not enough free space available it will be reallocated.
	Encode(*Wirebuf)
	// Decode decodes data from a DNS wire format in b, starting at p.
	// Decode may return a non nil Error if b is not in the correct format.
	// After Decode, p is adjusted to reflect the amount of data consumed from b.
	Decode(b []byte, p *int) os.Error
}
