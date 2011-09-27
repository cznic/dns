// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

// Package msg handles DNS messages.
package msg

import (
	"github.com/cznic/dns"
	"github.com/cznic/dns/rr"
	"github.com/cznic/mathutil"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var idgen struct {
	rng *mathutil.FC32
	mtx sync.Mutex
}

func init() {
	var err os.Error
	if idgen.rng, err = mathutil.NewFC32(math.MinInt32, math.MaxInt32, true); err != nil {
		panic(err)
	}
	go func() {
		for {
			idgen.mtx.Lock() // X++
			x := int64(idgen.rng.Next())
			idgen.rng.Seed(x + time.Nanoseconds())
			idgen.mtx.Unlock() // X--
			<-time.After((600 + x&0xFF) * 1e9)
		}
	}()
}

// GenID returns a new pseudo random message ID. GenID is safe for concurrent access.
func GenID() uint16 {
	idgen.mtx.Lock()         // X++
	defer idgen.mtx.Unlock() // X--
	return uint16(idgen.rng.Next())
}

// Header is the header section of a DNS message.
type Header struct {
	// A 16 bit identifier assigned by the program that
	// generates any kind of query.  This identifier is copied
	// the corresponding reply and can be used by the requester
	// to match up replies to outstanding queries.
	ID uint16
	// Field that specifies whether this message is a
	// query (false), or a response (true).
	QR bool
	// A four bit field that specifies kind of query in this
	// message.  This value is set by the originator of a query
	// and copied into the response.
	Opcode
	// Authoritative Answer - this bit is valid in responses,
	// and specifies that the responding name server is an
	// authority for the domain name in question section.
	// Note that the contents of the answer section may have
	// multiple owner names because of aliases.  The AA bit
	// corresponds to the name which matches the query name, or
	// the first owner name in the answer section.
	AA bool
	// TrunCation - specifies that this message was truncated
	// due to length greater than that permitted on the
	// transmission channel.
	TC bool
	// Recursion Desired - this bit may be set in a query and
	// is copied into the response.  If RD is set, it directs
	// the name server to pursue the query recursively.
	// Recursive query support is optional.
	RD bool
	// Recursion Available - this be is set or cleared in a
	// response, and denotes whether recursive query support is
	// available in the name server.
	RA bool
	// Reserved for future use.  Must be zero in all queries
	// and responses.
	Z bool
	// rfc2535: The AD (authentic data) bit indicates
	// in a response that all the data included in the answer and authority
	// portion of the response has been authenticated by the server
	// according to the policies of that server.
	AD bool
	// The CD (checking disabled)
	// bit indicates in a query that Pending (non-authenticated) data is
	// acceptable to the resolver sending the query.
	CD bool
	// Response code - this 4 bit field is set as part of
	// responses.
	RCODE
	// An unsigned 16 bit integer specifying the number of
	// entries in the question section.
	QDCOUNT uint16
	// An unsigned 16 bit integer specifying the number of
	// resource records in the answer section.
	ANCOUNT uint16
	// An unsigned 16 bit integer specifying the number of name
	// server resource records in the authority records
	// section.
	NSCOUNT uint16
	// An unsigned 16 bit integer specifying the number of
	// resource records in the additional records section.
	ARCOUNT uint16
}

func b2i(b bool) int {
	if b {
		return 1
	}

	return 0
}

func (h *Header) String() string {
	return fmt.Sprintf(
		"ID:%d QR:%t OPCODE:%s AA:%t TC:%t RD:%t RA:%t Z:%d AD:%d CD:%d RCODE:%s QDCOUNT:%d ANCOUNT:%d NSCOUNT:%d ARCOUNT:%d",
		h.ID, h.QR, h.Opcode, h.AA, h.TC, h.RD, h.RA, b2i(h.Z), b2i(h.AD), b2i(h.CD), h.RCODE, h.QDCOUNT, h.ANCOUNT, h.NSCOUNT, h.ARCOUNT,
	)
}

// Implementation of dns.Wirer
func (m *Header) Encode(b *dns.Wirebuf) {
	dns.Octets2(m.ID).Encode(b)
	var w uint16
	if m.QR {
		w |= 1
	}

	w <<= 4
	w |= uint16(m.Opcode) & 0xF

	w <<= 1
	if m.AA {
		w |= 1
	}
	w <<= 1
	if m.TC {
		w |= 1
	}
	w <<= 1
	if m.RD {
		w |= 1
	}
	w <<= 1
	if m.RA {
		w |= 1
	}

	w <<= 1
	if m.Z {
		w |= 1
	}

	w <<= 1
	if m.AD {
		w |= 1
	}

	w <<= 1
	if m.CD {
		w |= 1
	}

	w <<= 4
	w |= uint16(m.RCODE) & 0xF
	dns.Octets2(w).Encode(b)
	dns.Octets2(m.QDCOUNT).Encode(b)
	dns.Octets2(m.ANCOUNT).Encode(b)
	dns.Octets2(m.NSCOUNT).Encode(b)
	dns.Octets2(m.ARCOUNT).Encode(b)
}

// Implementation of dns.Wirer
func (m *Header) Decode(b []byte, pos *int) (err os.Error) {
	if err = (*dns.Octets2)(&m.ID).Decode(b, pos); err != nil {
		return
	}

	var w dns.Octets2
	if err = w.Decode(b, pos); err != nil {
		return
	}

	m.RCODE = RCODE(w & 0xF)
	w >>= 4
	m.CD = w&1 != 0
	w >>= 1
	m.AD = w&1 != 0
	w >>= 1
	m.Z = w&1 != 0
	w >>= 1
	m.RA = w&1 != 0
	w >>= 1
	m.RD = w&1 != 0
	w >>= 1
	m.TC = w&1 != 0
	w >>= 1
	m.AA = w&1 != 0
	w >>= 1
	m.Opcode = Opcode(w & 0xF)
	w >>= 4
	m.QR = w&1 != 0

	if w.Decode(b, pos); err != nil {
		return
	}

	m.QDCOUNT = uint16(w)

	if w.Decode(b, pos); err != nil {
		return
	}

	m.ANCOUNT = uint16(w)

	if w.Decode(b, pos); err != nil {
		return
	}

	m.NSCOUNT = uint16(w)

	if w.Decode(b, pos); err != nil {
		return
	}

	m.ARCOUNT = uint16(w)

	if m.Z {
		err = fmt.Errorf("invalid DNS message header Z:%t", m.Z)
	}
	return
}

// Message is a DNS message. (RFC 1035, Chapter 4, RFC2535)
type Message struct {
	Header
	Question          // the question for the name server
	Answer     rr.RRs // RRs answering the question
	Authority  rr.RRs // RRs pointing toward an authority
	Additional rr.RRs // RRs holding additional information
}

// New returns a newly created Message. Initialized fields of Message are:
//	Header.ID
func New() *Message {
	return &Message{Header: Header{ID: GenID()}}
}

// Implementation of dns.Wirer
func (m *Message) Encode(b *dns.Wirebuf) {
	m.Header.QDCOUNT = uint16(len(m.Question))
	m.Header.ANCOUNT = uint16(len(m.Answer))
	m.Header.NSCOUNT = uint16(len(m.Authority))
	m.Header.ARCOUNT = uint16(len(m.Additional))
	m.Header.Encode(b)
	for _, q := range m.Question {
		q.Encode(b)
	}
	for _, r := range m.Answer {
		r.Encode(b)
	}
	for _, r := range m.Authority {
		r.Encode(b)
	}
	for _, r := range m.Additional {
		r.Encode(b)
	}
}

// Implementation of dns.Wirer
func (m *Message) Decode(b []byte, pos *int) (err os.Error) {
	if err = m.Header.Decode(b, pos); err != nil {
		return
	}

	m.Question = make([]*QuestionItem, m.QDCOUNT)
	if err = m.Question.Decode(b, pos); err != nil {
		return
	}

	if err = decodeRRs(&m.Answer, m.ANCOUNT, b, pos); err != nil {
		return
	}

	if err = decodeRRs(&m.Authority, m.NSCOUNT, b, pos); err != nil {
		return
	}

	if err = decodeRRs(&m.Additional, m.ARCOUNT, b, pos); err != nil {
		return
	}

	if *pos != len(b) {
		return fmt.Errorf("Message.Decode() - %d extra bytes", *pos-len(b))
	}

	return
}

func (m *Message) String() string {
	a := []string{m.Header.String()}
	if len(m.Question) != 0 {
		a = append(a, m.Question.String())
	}
	if len(m.Answer) != 0 {
		a = append(a, m.answerString())
	}
	if len(m.Authority) != 0 {
		a = append(a, m.authorityString())
	}
	if len(m.Additional) != 0 {
		a = append(a, m.additionalString())
	}
	return strings.Join(a, "\n")
}

func (m *Message) answerString() string {
	a := []string{}
	for i, it := range m.Answer {
		a = append(a, fmt.Sprintf("Answer[%d]: %s", i, it))
	}
	return strings.Join(a, "\n")
}

func (m *Message) authorityString() string {
	a := []string{}
	for i, it := range m.Authority {
		a = append(a, fmt.Sprintf("Authority[%d]: %s", i, it))
	}
	return strings.Join(a, "\n")
}

func (m *Message) additionalString() string {
	a := []string{}
	for i, it := range m.Additional {
		a = append(a, fmt.Sprintf("Additional[%d]: %s", i, it))
	}
	return strings.Join(a, "\n")
}

// Send sends m through conn and returns an Error of any.
// If the conn is a *net.TCPConn then the 2 byte msg len is prepended.
func (m *Message) Send(conn net.Conn) (err os.Error) {
	//TODO use this from Exchange and friends
	w := dns.NewWirebuf()
	m.Encode(w)

	var nw int
	if _, ok := conn.(*net.TCPConn); ok {
		n := len(w.Buf)
		b := []byte{byte(n >> 8), byte(n)}
		if nw, err = conn.Write(b); err != nil {
			return
		}

		if nw != len(w.Buf) {
			err = fmt.Errorf("Message.Send: write %d != %d", nw, len(b))
		}
	}

	if nw, err = conn.Write(w.Buf); err != nil {
		return
	}

	if nw != len(w.Buf) {
		err = fmt.Errorf("Message.Send: write %d != %d", nw, len(w.Buf))
	}
	return
}

// ReceiveTCP attempts to read a DNS message m through conn and returns an Error if any.
// ReceiveTCP uses rxbuf for receiving the message. ReceiveTCP can hang forever if the
// conn doesn't have appropriate read timeout already set.
// Returned n reflects the number of bytes revecied to rxbuf.
// The 2 byte msg len prefix is expected firstly.
// The two prefix bytes are not reflected in the returned size 'n'.
func (m *Message) ReceiveTCP(conn *net.TCPConn, rxbuf []byte) (n int, err os.Error) {
	b := make([]byte, 2)
	if n, err = io.ReadFull(conn, b); err != nil {
		return
	}

	n = int(b[0])<<8 | int(b[1])
	nr := 0
	rxbuf = rxbuf[:n]
	if nr, err = io.ReadFull(conn, rxbuf); err != nil {
		return nr, fmt.Errorf("msg.ReceiveBuf size=%d(got %d): %s", n, nr, err)
	}

	p := 0
	err = m.Decode(rxbuf, &p)
	return
}

// ReadceiveUDP reads a UDP packet from conn, copying the payload into rxbuf.
// It returns the number of bytes copied into b and the address that was on the packet.
// ReceiveUDP can hang forever if the conn doesn't have appropriate read timeout already set.
// Returned n reflects the number of bytes revecied to rxbuf.
func (m *Message) ReceiveUDP(conn *net.UDPConn, rxbuf []byte) (n int, addr *net.UDPAddr, err os.Error) {
	if n, addr, err = conn.ReadFromUDP(rxbuf); err != nil {
		return
	}

	p := 0
	err = m.Decode(rxbuf[:n], &p)
	return
}

// ExchangeWire exchanges a msg 'w' already in wire format through conn and returns a reply or an Error if any.
// ExchangeBuf uses rxbuf for receiving the reply. ExchangeWire can hang forever if the
// conn doesn't have appropriate read and/or write timeouts already set.
// Returned n reflects the number of bytes revecied to rxbuf.
func ExchangeWire(conn net.Conn, w, rxbuf []byte) (n int, reply *Message, err os.Error) {
	var nw int
	if nw, err = conn.Write(w); err != nil {
		return
	}

	if nw != len(w) {
		return 0, nil, fmt.Errorf("ExchangeWire: write %d != %d", nw, len(w))
	}

	if n, err = conn.Read(rxbuf); err != nil {
		return
	}

	reply = &Message{}
	p := 0
	if err = reply.Decode(rxbuf[:n], &p); err != nil {
		reply = nil
	}
	return
}

// ExchangeBuf exchanges m through conn and returns a reply or an Error if any.
// ExchangeBuf uses rxbuf for receiving the reply. ExchangeBuf can hang forever if the
// conn doesn't have appropriate read and/or write timeouts already set.
// Returned n reflects the number of bytes revecied to rxbuf.
func (m *Message) ExchangeBuf(conn net.Conn, rxbuf []byte) (n int, reply *Message, err os.Error) {
	w := dns.NewWirebuf()
	m.Encode(w)
	return ExchangeWire(conn, w.Buf, rxbuf)
}

// Exchange invokes ExchangeBuf with a private rxbuf of rxbufsize bytes.
func (m *Message) Exchange(conn net.Conn, rxbufsize int) (reply *Message, err os.Error) {
	_, reply, err = m.ExchangeBuf(conn, make([]byte, rxbufsize))
	return
}

// ExchangeReply is the type of the ExchangeChan.
type ExchangeReply struct {
	*Message
	os.Error
}

// ExchangeChan is the type of the channel used to report ExchangeReply from GoExchangeBuf and GoExchange.
type ExchangeChan chan ExchangeReply

// GoExchangeBuf invokes ExchangeBuf in a separate goroutine and reports the result back using
// the supplied reply channel. The goroutine returns after sending the result. 
// Channel communication errors are ignored, so e.g. if the reply channel is closed when the goroutine
// wants to send results back through it, the goroutine returns without panic.
// The reply channel may be nil on invocation, then it is created by this method
// (buffered with a default size).
func (m *Message) GoExchangeBuf(conn net.Conn, rxbuf []byte, reply ExchangeChan) ExchangeChan {
	if reply == nil {
		reply = make(ExchangeChan, 100)
	}
	go func() {
		_, rx, err := m.ExchangeBuf(conn, rxbuf)
		defer func() {
			_ = recover() // catch and discard panic due to e.g. possibly already closed reply channel
		}()
		reply <- ExchangeReply{rx, err}
	}()
	return reply
}

// GoExchange invokes GoExchangeBuf with a private rxbuf of rxbufsize bytes.
func (m *Message) GoExchange(conn net.Conn, rxbufsize int, reply ExchangeChan) ExchangeChan {
	return m.GoExchangeBuf(conn, make([]byte, rxbufsize), reply)
}

// Opcode is the type of the Opcode field in a Header.
type Opcode byte

// Header.Opcode values.
const (
	QUERY  Opcode = iota // 0: a standard query (QUERY)
	IQUERY               // 1: an inverse query (IQUERY)
	STATUS               // 2: a server status request (STATUS)
	_                    // 3: Unassigned
	NOTIFY               // 4: Notify [RFC1996]
)

func (o Opcode) String() string {
	switch o {
	case QUERY:
		return "QUERY"
	case IQUERY:
		return "IQUERY"
	case STATUS:
		return "STATUS"
	case NOTIFY:
		return "NOTIFY"
	}
	return fmt.Sprintf("%d!", byte(o))
}

// QTYPE fields appear in the question part of a query.  QTYPES are a
// superset of rr.TYPEs, hence all TYPEs are valid QTYPEs. 
type QType uint16

// QTYPE codes
const (
	_ QType = iota

	QTYPE_A          //  1 a host address                              [RFC1035]
	QTYPE_NS         //  2 an authoritative name server                [RFC1035]
	QTYPE_MD         //  3 a mail destination (Obsolete - use MX)      [RFC1035]
	QTYPE_MF         //  4 a mail forwarder (Obsolete - use MX)        [RFC1035]
	QTYPE_CNAME      //  5 the canonical name for an alias             [RFC1035]
	QTYPE_SOA        //  6 marks the start of a zone of authority      [RFC1035]
	QTYPE_MB         //  7 a mailbox domain name (EXPERIMENTAL)        [RFC1035]
	QTYPE_MG         //  8 a mail group member (EXPERIMENTAL)          [RFC1035]
	QTYPE_MR         //  9 a mail rename domain name (EXPERIMENTAL     [RFC1035]
	QTYPE_NULL       // 10 a null RR (EXPERIMENTAL)                    [RFC1035]
	QTYPE_WKS        // 11 a well known service description            [RFC1035]
	QTYPE_PTR        // 12 a domain name pointer                       [RFC1035]
	QTYPE_HINFO      // 13 host information                            [RFC1035]
	QTYPE_MINFO      // 14 mailbox or mail list information            [RFC1035]
	QTYPE_MX         // 15 mail exchange                               [RFC1035]
	QTYPE_TXT        // 16 text strings                                [RFC1035]
	QTYPE_RP         // 17 for Responsible Person                      [RFC1183]
	QTYPE_AFSDB      // 18 for AFS Data Base location                  [RFC1183][RFC5864]
	QTYPE_X25        // 19 for X.25 PSDN address                       [RFC1183]
	QTYPE_ISDN       // 20 for ISDN address                            [RFC1183]
	QTYPE_RT         // 21 for Route Through                           [RFC1183]
	QTYPE_NSAP       // 22 for NSAP address, NSAP style A record       [RFC1706]
	QTYPE_NSAP_PTR   // 23 for domain name pointer, NSAP style         [RFC1348]
	QTYPE_SIG        // 24 for security signature                      [RFC4034][RFC3755][RFC2535]
	QTYPE_KEY        // 25 for security key                            [RFC4034][RFC3755][RFC2535]
	QTYPE_PX         // 26 X.400 mail mapping information              [RFC2163]
	QTYPE_GPOS       // 27 Geographical Position                       [RFC1712]
	QTYPE_AAAA       // 28 IP6 Address                                 [RFC3596]
	QTYPE_LOC        // 29 Location Information                        [RFC1876]
	QTYPE_NXT        // 30 Next Domain - OBSOLETE                      [RFC3755][RFC2535]
	QTYPE_EID        // 31 Endpoint Identifier                         [Patton]
	QTYPE_NIMLOC     // 32 Nimrod Locator                              [Patton]
	QTYPE_SRV        // 33 Server Selection                            [RFC2782]
	QTYPE_ATMA       // 34 ATM Address                                 [ATMDOC]
	QTYPE_NAPTR      // 35 Naming Authority Pointer                    [RFC2915][RFC2168][RFC3403]
	QTYPE_KX         // 36 Key Exchanger                               [RFC2230]
	QTYPE_CERT       // 37 CERT                                        [RFC4398]
	QTYPE_A6         // 38 A6 (Experimental)                           [RFC3226][RFC2874]
	QTYPE_DNAME      // 39 DNAME                                       [RFC2672]
	QTYPE_SINK       // 40 SINK                                        [Eastlake]
	QTYPE_OPT        // 41 OPT                                         [RFC2671]
	QTYPE_APL        // 42 APL                                         [RFC3123]
	QTYPE_DS         // 43 Delegation Signer                           [RFC4034][RFC3658]
	QTYPE_SSHFP      // 44 SSH Key Fingerprint                         [RFC4255]
	QTYPE_IPSECKEY   // 45 IPSECKEY                                    [RFC4025]
	QTYPE_RRSIG      // 46 RRSIG                                       [RFC4034][RFC3755]
	QTYPE_NSEC       // 47 NSEC                                        [RFC4034][RFC3755]
	QTYPE_DNSKEY     // 48 DNSKEY                                      [RFC4034][RFC3755]
	QTYPE_DHCID      // 49 DHCID                                       [RFC4701]
	QTYPE_NSEC3      // 50 NSEC3                                       [RFC5155]
	QTYPE_NSEC3PARAM // 51 NSEC3PARAM                                  [RFC5155]
)

const (
	_ QType = iota + 54

	QTYPE_HIP    // 55 Host Identity Protocol                      [RFC5205]
	QTYPE_NINFO  // 56 NINFO                                       [Reid]
	QTYPE_RKEY   // 57 RKEY                                        [Reid]
	QTYPE_TALINK // 58 Trust Anchor LINK                           [Wijngaards]
	QTYPE_CDS    // 59 Child DS                                    [Barwood]
)

const (
	_ QType = iota + 98

	QTYPE_SPF    //  99                                             [RFC4408]
	QTYPE_UINFO  // 100                                             [IANA-Reserved]
	QTYPE_UID    // 101                                             [IANA-Reserved]
	QTYPE_GID    // 102                                             [IANA-Reserved]
	QTYPE_UNSPEC // 103                                             [IANA-Reserved]
)

const (
	_ QType = iota + 248

	QTYPE_TKEY  // 249 Transaction Key                            [RFC2930]
	QTYPE_TSIG  // 250 Transaction Signature                      [RFC2845]
	QTYPE_IXFR  // 251 incremental transfer                       [RFC1995]
	QTYPE_AXFR  // 252 transfer of an entire zone                 [RFC1035][RFC5936]
	QTYPE_MAILB // 253 mailbox-related RRs (MB, MG or MR)         [RFC1035]
	QTYPE_MAILA // 254 mail agent RRs (Obsolete - see MX)         [RFC1035]
	QTYPE_STAR  // 255 A request for all records                  [RFC1035]
	QTYPE_URI   // 256 URI                                        [Faltstrom]
	QTYPE_CAA   // 257 Certification Authority Authorization      [Hallam-Baker]
)

const (
	_ QType = iota + 0x7FFF

	QTYPE_TA  // 32768   DNSSEC Trust Authorities               [Weiler]           2005-12-13
	QTYPE_DLV // 32769   DNSSEC Lookaside Validation            [RFC4431]
)

const (
	_ QType = iota + 0xFEFF

	QTYPE_NODATA // A pseudo type in the "reserved for private use" area
	QTYPE_NXDOMAIN
)

var qtypeStr = map[QType]string{
	QTYPE_A6:         "A6",
	QTYPE_A:          "A",
	QTYPE_AAAA:       "AAAA",
	QTYPE_AFSDB:      "AFSDB",
	QTYPE_APL:        "APL",
	QTYPE_ATMA:       "ATMA",
	QTYPE_AXFR:       "AXFR",
	QTYPE_CAA:        "CAA",
	QTYPE_CDS:        "CDS",
	QTYPE_CERT:       "CERT",
	QTYPE_CNAME:      "CNAME",
	QTYPE_DHCID:      "DHCID",
	QTYPE_DLV:        "DLV",
	QTYPE_DNAME:      "DNAME",
	QTYPE_DNSKEY:     "DNSKEY",
	QTYPE_DS:         "DS",
	QTYPE_EID:        "EID",
	QTYPE_GID:        "GID",
	QTYPE_GPOS:       "GPOS",
	QTYPE_HINFO:      "HINFO",
	QTYPE_HIP:        "HIP",
	QTYPE_IPSECKEY:   "IPSECKEY",
	QTYPE_ISDN:       "ISDN",
	QTYPE_IXFR:       "IXFR",
	QTYPE_KEY:        "KEY",
	QTYPE_KX:         "KX",
	QTYPE_LOC:        "LOC",
	QTYPE_MAILA:      "MAILA",
	QTYPE_MAILB:      "MAILB",
	QTYPE_MB:         "MB",
	QTYPE_MD:         "MD",
	QTYPE_MF:         "MF",
	QTYPE_MG:         "MG",
	QTYPE_MINFO:      "MINFO",
	QTYPE_MR:         "MR",
	QTYPE_MX:         "MX",
	QTYPE_NAPTR:      "NAPTR",
	QTYPE_NIMLOC:     "NIMLOC",
	QTYPE_NINFO:      "NINFO",
	QTYPE_NODATA:     "NODATA",
	QTYPE_NS:         "NS",
	QTYPE_NSAP:       "NSAP",
	QTYPE_NSAP_PTR:   "NSAP-PTR",
	QTYPE_NSEC3:      "NSEC3",
	QTYPE_NSEC3PARAM: "NSEC3PARAM",
	QTYPE_NSEC:       "NSEC",
	QTYPE_NULL:       "NULL",
	QTYPE_NXDOMAIN:   "NXDOMAIN",
	QTYPE_NXT:        "NXT",
	QTYPE_PTR:        "PTR",
	QTYPE_PX:         "PX",
	QTYPE_RKEY:       "RKEY",
	QTYPE_RP:         "RP",
	QTYPE_RRSIG:      "RRSIG",
	QTYPE_RT:         "RT",
	QTYPE_SIG:        "SIG",
	QTYPE_SINK:       "SINK",
	QTYPE_SOA:        "SOA",
	QTYPE_SPF:        "SPF",
	QTYPE_SRV:        "SRV",
	QTYPE_SSHFP:      "SSHFP",
	QTYPE_STAR:       "*",
	QTYPE_TA:         "TA",
	QTYPE_TALINK:     "TALINK",
	QTYPE_TKEY:       "TKEY",
	QTYPE_TSIG:       "TSIG",
	QTYPE_TXT:        "TXT",
	QTYPE_UID:        "UID",
	QTYPE_UINFO:      "UINFO",
	QTYPE_UNSPEC:     "UNSPEC",
	QTYPE_URI:        "URI",
	QTYPE_WKS:        "WKS",
	QTYPE_X25:        "X25",
}

func (n QType) String() (s string) {
	var ok bool
	if s, ok = qtypeStr[n]; !ok {
		panic(fmt.Errorf("unexpected QType %d", uint16(n)))
	}
	return
}

// Question is the question section of a DNS message.
type Question []*QuestionItem

// Implementation of dns.Wirer
func (q Question) Decode(b []byte, pos *int) (err os.Error) {
	for i := range q {
		qi := &QuestionItem{}
		if err = qi.Decode(b, pos); err != nil {
			return
		}

		q[i] = qi
	}
	return
}

func (q *Question) Append(qname string, qtype QType, qclass rr.Class) {
	*q = append(*q, &QuestionItem{qname, qtype, qclass})
}

func (q *Question) A(qname string, qclass rr.Class) {
	q.Append(qname, QTYPE_A, qclass)
}

func (q *Question) AAAA(qname string, qclass rr.Class) {
	q.Append(qname, QTYPE_AAAA, qclass)
}

func (q *Question) NS(qname string, qclass rr.Class) {
	q.Append(qname, QTYPE_NS, qclass)
}

func (q *Question) PTR(qname string, qclass rr.Class) {
	q.Append(qname, QTYPE_PTR, qclass)
}

func (q *Question) STAR(qname string, qclass rr.Class) {
	q.Append(qname, QTYPE_STAR, qclass)
}

func (q *Question) TXT(qname string, qclass rr.Class) {
	q.Append(qname, QTYPE_TXT, qclass)
}

func (q *Question) String() string {
	a := []string{}
	for i, qi := range *q {
		a = append(a, fmt.Sprintf("Question[%d]: %s", i, qi))
	}
	return strings.Join(a, "\n")
}

// QuestionItem is an item of the question section of a DNS message.
type QuestionItem struct {
	// A domain name represented as a sequence of labels, where
	// each label consists of a length octet followed by that
	// number of octets.  The domain name terminates with the
	// zero length octet for the null label of the root.  Note
	// that this field may be an odd number of octets; no
	// padding is used.
	QNAME string
	// A two octet code which specifies the type of the query.
	// The values for this field include all codes valid for a
	// TYPE field, together with some more general codes which
	// can match more than one type of RR.
	QTYPE QType
	// A two octet code that specifies the class of the query.
	// For example, the QCLASS field is IN for the Internet.
	QCLASS rr.Class
}

func (m *QuestionItem) String() string {
	return fmt.Sprintf("QNAME:%q QTYPE:%s QCLASS:%s", m.QNAME, m.QTYPE, m.QCLASS)
}

// Implementation of dns.Wirer
func (m *QuestionItem) Encode(b *dns.Wirebuf) {
	dns.DomainName(m.QNAME).Encode(b)
	dns.Octets2(m.QTYPE).Encode(b)
	dns.Octets2(m.QCLASS).Encode(b)
}

// Implementation of dns.Wirer
func (m *QuestionItem) Decode(b []byte, pos *int) (err os.Error) {
	if err = (*dns.DomainName)(&m.QNAME).Decode(b, pos); err != nil {
		return
	}

	if err = (*dns.Octets2)(&m.QTYPE).Decode(b, pos); err != nil {
		return
	}

	if err = m.QCLASS.Decode(b, pos); err != nil {
		return
	}

	return
}

// RCODE is the type of the RCODE field in a Header.
type RCODE byte

// RCODE values.
const (
	// 0               No error condition
	RC_NO_ERROR RCODE = iota
	// 1               Format error - The name server was
	//                 unable to interpret the query.
	RC_FORMAT_ERROR
	// 2               Server failure - The name server was
	//                 unable to process this query due to a
	//                 problem with the name server.
	RC_SERVER_FAILURE
	// 3               Name Error - Meaningful only for
	//                 responses from an authoritative name
	//                 server, this code signifies that the
	//                 domain name referenced in the query does
	//                 not exist.
	RC_NAME_ERROR
	// 4               Not Implemented - The name server does
	//                 not support the requested kind of query.
	RC_NOT_IMPLEMENETD
	// 5               Refused - The name server refuses to
	//                 perform the specified operation for
	//                 policy reasons.  For example, a name
	//                 server may not wish to provide the
	//                 information to the particular requester,
	//                 or a name server may not wish to perform
	//                 a particular operation (e.g., zone
	//                 transfer) for particular data.
	RC_REFUSED
	// 6-15            Reserved for future use.
	_
)

func (r RCODE) String() string {
	switch r {
	case RC_NO_ERROR:
		return "RC_NO_ERROR"
	case RC_FORMAT_ERROR:
		return "RC_FORMAT_ERROR"
	case RC_SERVER_FAILURE:
		return "RC_SERVER_FAILURE"
	case RC_NAME_ERROR:
		return "RC_NAME_ERROR"
	case RC_NOT_IMPLEMENETD:
		return "RC_NOT_IMPLEMENETD"
	case RC_REFUSED:
		return "RC_REFUSED"
	}
	return fmt.Sprint("%d!", r)
}

func decodeRRs(rrs *rr.RRs, n uint16, b []byte, pos *int) (err os.Error) {
	if n == 0 {
		return
	}

	*rrs = make(rr.RRs, n)
	for i := range *rrs {
		r := &rr.RR{}
		if err = r.Decode(b, pos); err != nil {
			return
		}

		(*rrs)[i] = r
	}
	return
}
