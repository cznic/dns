// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

package main

import (
	"fmt"
	"github.com/cznic/dns/msg"
	"github.com/cznic/dns/pcat"
	"github.com/cznic/dns/rr"
	"log"
)

func (j *job) cmpRecords(id int, ra, rb *pcat.Record) {
	j.cmpMsg(id, "Q", ra.Query, rb.Query)
	if j.cmpMsg(id, "R", ra.Reply, rb.Reply) {
		j.totalRDiffs++
	}
}

func (j *job) cmpMsg(id int, qr string, ba, bb []byte) (diff bool) {
	ma, mb := &msg.Message{}, &msg.Message{}
	p := 0
	if err := ma.Decode(ba, &p, nil); err != nil {
		log.Fatal("internal error", err)
	}

	p = 0
	if err := mb.Decode(bb, &p, nil); err != nil {
		log.Fatal("internal error", err)
	}

	missRRcnt := 1
	diff = diff || j.cmpMsgHeader(id, qr, ma.Header, mb.Header)
	diff = diff || j.cmpMsgQuestion(id, qr, ma.Question, mb.Question)
	diff = diff || j.cmpMsgSection(id, &missRRcnt, qr, "Answer", ma.Answer, mb.Answer)
	diff = diff || j.cmpMsgSection(id, &missRRcnt, qr, "Authority", ma.Authority, mb.Authority)
	diff = diff || j.cmpMsgSection(id, &missRRcnt, qr, "Additional", ma.Additional, mb.Additional)
	return
}

func (j *job) cmpMsgHeader(id int, qr string, ha, hb msg.Header) (diff bool) {
	if g, e := ha.ID, hb.ID; g != e {
		diff = true
		j.err(id, 1, DIFF_HDR_ID, "%s: %v != %v", qr, g, e)
	}
	if g, e := ha.QR, hb.QR; g != e {
		diff = true
		j.err(id, 1, DIFF_HDR_QR, "%s: %v != %v", qr, g, e)
	}
	if g, e := ha.Opcode, hb.Opcode; g != e {
		diff = true
		j.err(id, 1, DIFF_HDR_Opcode, "%s: %v != %v", qr, g, e)
	}
	if g, e := ha.AA, hb.AA; g != e {
		diff = true
		j.err(id, 1, DIFF_HDR_AA, "%s: %v != %v", qr, g, e)
	}
	if g, e := ha.TC, hb.TC; g != e {
		diff = true
		j.err(id, 1, DIFF_HDR_TC, "%s: %v != %v", qr, g, e)
	}
	if g, e := ha.RD, hb.RD; g != e {
		diff = true
		j.err(id, 1, DIFF_HDR_RD, "%s: %v != %v", qr, g, e)
	}
	if g, e := ha.RA, hb.RA; g != e {
		diff = true
		j.err(id, 1, DIFF_HDR_RA, "%s: %v != %v", qr, g, e)
	}
	if g, e := ha.Z, hb.Z; g != e {
		diff = true
		j.err(id, 1, DIFF_HDR_Z, "%s: %v != %v", qr, g, e)
	}
	if g, e := ha.AD, hb.AD; g != e {
		diff = true
		j.err(id, 1, DIFF_HDR_AD, "%s: %v != %v", qr, g, e)
	}
	if g, e := ha.CD, hb.CD; g != e {
		diff = true
		j.err(id, 1, DIFF_HDR_CD, "%s: %v != %v", qr, g, e)
	}
	if g, e := ha.RCODE, hb.RCODE; g != e {
		diff = true
		j.err(id, 1, DIFF_HDR_RCODE, "%s: %v != %v", qr, g, e)
	}
	if g, e := ha.QDCOUNT, hb.QDCOUNT; g != e {
		diff = true
		j.err(id, 1, DIFF_HDR_QDCOUNT, "%s: %v != %v", qr, g, e)
	}
	if g, e := ha.ANCOUNT, hb.ANCOUNT; g != e {
		diff = true
		j.err(id, 1, DIFF_HDR_ANCOUNT, "%s: %v != %v", qr, g, e)
	}
	if g, e := ha.NSCOUNT, hb.NSCOUNT; g != e {
		diff = true
		j.err(id, 1, DIFF_HDR_NSCOUNT, "%s: %v != %v", qr, g, e)
	}
	if g, e := ha.ARCOUNT, hb.ARCOUNT; g != e {
		diff = true
		j.err(id, 1, DIFF_HDR_ARCOUNT, "%s: %v != %v", qr, g, e)
	}
	return
}

func (j *job) cmpMsgQuestion(id int, qr string, qa, qb msg.Question) (diff bool) {
	m := map[string]bool{}
	for _, item := range qa {
		k := fmt.Sprintf("A%s %s %s", item.QNAME, item.QTYPE, item.QCLASS)
		if _, ok := m[k]; ok {
			j.err(id, 1, DUP_QI, "%s: %s", qr, k[1:])
		}
		m[k] = false
	}
	for _, item := range qb {
		k := fmt.Sprintf("B%s %s %s", item.QNAME, item.QTYPE, item.QCLASS)
		if _, ok := m[k]; ok {
			j.err(id, 1, DUP_QI, "%s: %s", qr, k[1:])
		}
		m[k] = true
	}
	for k, v := range m {
		switch v {
		case false: // A
			if _, ok := m["B"+k[1:]]; !ok {
				diff = true
				j.err(id, 1, MISSING_QI, "%s: %s", qr, k[1:])
			}
		case true: // B
			if _, ok := m["A"+k[1:]]; !ok {
				diff = true
				j.err(id, 1, MISSING_QI, "%s: %s", qr, k[1:])
			}
		}
	}
	return
}

func (j *job) cmpMsgSection(id int, missRRcnt *int, qr, sec string, a, b rr.RRs) (diff bool) {
	m := map[string]struct{}{}
	for _, item := range a {
		k := fmt.Sprintf("A%s", item)
		if _, ok := m[k]; ok {
			j.err(id, 1, DUP_RR, "%s %s: %s", qr, sec, k[1:])
		}
		m[k] = struct{}{}
	}
	for _, item := range b {
		k := fmt.Sprintf("B%s", item)
		if _, ok := m[k]; ok {
			j.err(id, 1, DUP_RR, "%s %s: %s", qr, sec, k[1:])
		}
		m[k] = struct{}{}
	}
	for k, _ := range m {
		k0 := k[1:]
		switch k[0] {
		case 'A':
			if _, ok := m["B"+k0]; !ok {
				diff = true
				j.err(id, *missRRcnt, MISSING_RR, "%s %s(A): %s", qr, sec, k[1:])
				*missRRcnt = 0
			}
		case 'B':
			if _, ok := m["A"+k0]; !ok {
				diff = true
				j.err(id, *missRRcnt, MISSING_RR, "%s %s(B): %s", qr, sec, k[1:])
				*missRRcnt = 0
			}
		}
	}
	return
}
