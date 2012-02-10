// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

package main

import (
	"encoding/hex"
	"fmt"
	"github.com/cznic/dns/msg"
	"github.com/cznic/dns/pcat"
	"log"
	"path"
	"sort"
)

func diff(a, b int) int {
	if a > b {
		return a - b
	}

	return b - a
}

func hdump(emitId func(), name string, r *pcat.Record) {
	emitId()
	fmt.Printf("#--%s\n#--Query\n%s#--Reply\n%s\n",
		name,
		hex.Dump(r.Query),
		hex.Dump(r.Reply),
	)
}

func rdump(emitId func(), name string, rp *pcat.Record) {
	r := *rp
	r.Query = append([]byte{}, rp.Query...)
	r.Reply = append([]byte{}, rp.Reply...)
	emitId()
	var qs, rs string
	qm, p := &msg.Message{}, 0
	switch err := qm.Decode(r.Query, &p, nil); err == nil {
	case true:
		qs = qm.String()
	case false:
		qs = err.Error()
	}
	rm, p := &msg.Message{}, 0
	switch err := rm.Decode(r.Reply, &p, nil); err == nil {
	case true:
		rs = rm.String()
	case false:
		rs = err.Error()
	}
	fmt.Printf("#--%s\n#--Query\n%s\n#--Reply\n%s\n\n", name, qs, rs)
}

func do(j *job) {
	defer j.summary()

	xfrom := sort.SearchInts(j.index, *j.optFrom)
	xto := len(j.index)
	if max := *j.optMax; max >= 0 && xto-xfrom > max {
		xto = xfrom + max
	}

	j.fna, j.fnb = path.Base(j.fna), path.Base(j.fnb)
	if j.fna == j.fnb {
		j.fna += "(A)"
		j.fnb += "(B)"
	}

	var emitedId bool
	var id int

	emitId := func() {
		if emitedId {
			return
		}

		fmt.Printf("#==%d\n", id)
		emitedId = true
	}

	for _, id = range j.index[xfrom:xto] {
		emitedId = false

		// Get the records, dump if requested
		ra, haveA, err := j.db.RGet(1, id)
		if err != nil {
			log.Fatal(err)
		}

		if haveA {
			if *j.optWire {
				hdump(emitId, j.fna, &ra)
			}
			if *j.optReadable {
				rdump(emitId, j.fna, &ra)
			}
		}

		rb, haveB, err := j.db.RGet(2, id)
		if err != nil {
			log.Fatal(err)
		}

		if haveB {
			if *j.optWire {
				hdump(emitId, j.fnb, &rb)
			}
			if *j.optReadable {
				rdump(emitId, j.fnb, &rb)
			}
		}

		// Check we can compare
		if haveA != haveB {
			var n string
			switch {
			case !haveA:
				n = j.fna
			case !haveB:
				n = j.fnb
			}
			j.err(id, 1, NO_REC, "%s:%d", n, id)
		}

		// Compare wire formats
		if haveA && haveB {
			if la, lb := len(ra.Query), len(rb.Query); *j.optVerbose && la != lb {
				j.err(
					id,
					diff(la, lb),
					DIFF_Q_BYTES, "%s:%d:%d bytes vs %s:%d:%d bytes",
					j.fna, id, la,
					j.fnb, id, lb,
				)
				if *j.optVerbose && !*j.optWire {
					fmt.Printf(
						"#--%s:Query\n%s\n#--%s:Query\n%s\n",
						j.fna, hex.Dump(ra.Query),
						j.fnb, hex.Dump(rb.Query),
					)
				}
			}
			if la, lb := len(ra.Reply), len(rb.Reply); *j.optVerbose && la != lb {
				j.err(
					id,
					diff(la, lb),
					DIFF_R_BYTES, "%s:%d:%d bytes vs %s:%d:%d bytes",
					j.fna, id, la,
					j.fnb, id, lb,
				)
				if *j.optVerbose && !*j.optWire {
					fmt.Printf(
						"#--%s:Reply\n%s\n#--%s:Reply\n%s\n",
						j.fna, hex.Dump(ra.Reply),
						j.fnb, hex.Dump(rb.Reply),
					)
				}
			}
		}

		// Check malformations
		var msgQA, msgRA, msgQB, msgRB *msg.Message
		var decodeErrQA, decodeErrRA, decodeErrQB, decodeErrRB error
		if haveA {
			msgQA = &msg.Message{}
			p := 0
			if decodeErrQA = msgQA.Decode(ra.Query, &p, nil); decodeErrQA != nil {
				j.err(id, 1, INVALID_QUERY, "%s:%d: %s", j.fna, id, decodeErrQA)
			}
			msgRA = &msg.Message{}
			p = 0
			if decodeErrRA = msgRA.Decode(ra.Reply, &p, nil); decodeErrRA != nil {
				j.err(id, 1, INVALID_REPLY, "%s:%d: %s", j.fna, id, decodeErrRA)
			}
		}
		if haveB {
			msgQB = &msg.Message{}
			p := 0
			if decodeErrQB = msgQB.Decode(rb.Query, &p, nil); decodeErrQB != nil {
				j.err(id, 1, INVALID_QUERY, "%s:%d: %s", j.fnb, id, decodeErrQB)
			}
			msgRB = &msg.Message{}
			p = 0
			if decodeErrRB = msgRB.Decode(rb.Reply, &p, nil); decodeErrRB != nil {
				j.err(id, 1, INVALID_REPLY, "%s:%d: %s", j.fnb, id, decodeErrRB)
			}
		}

		// Compare (if possible)
		if haveA && haveB &&
			decodeErrQA == nil && decodeErrRA == nil && decodeErrQB == nil && decodeErrRB == nil {
			j.total++
			j.cmpRecords(id, &ra, &rb)
			if *j.optSOC {
				j.compression(id, "Q(A)", ra.Query)
				j.compression(id, "R(A)", ra.Reply)
				j.compression(id, "Q(B)", rb.Query)
				j.compression(id, "R(B)", rb.Reply)
			}
		}
	}
}
