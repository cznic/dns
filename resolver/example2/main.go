// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

// +build ignore

package main

import (
	"fmt"
	"github.com/cznic/dns"
	"github.com/cznic/dns/msg"
	"github.com/cznic/dns/resolver"
	"github.com/cznic/dns/rr"
	"log"
)

func main() {
	r, err := resolver.New("", "", dns.NewLogger(nil, dns.LOG_DEBUG))
	if err != nil {
		log.Fatal(err)
	}

	answer, redirects, result, err := r.Lookup(
		"3.7.*.rp.secret-wg.org",
		msg.QTYPE_TXT,
		rr.CLASS_IN,
		true,
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf(`
---- Answer:
%s
---- Redirects:
%s
---- Result: %s
`,
		answer, redirects, resolver.LookupResultStr[result],
	)
}
