package main

import (
	"cznic/dns"
	"cznic/dns/msg"
	"cznic/dns/resolver"
	"cznic/dns/rr"
	"fmt"
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
