// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

// Package dns collects some DNS common stuff.
package dns

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"
)

const timeLayout = "20060102150405"

// DefaultLocalNameServer return the IP of the default local DNS server
func DefaultLocalNameServer() net.IP {
	return net.ParseIP("127.0.0.1")
}

func Host2domain(hostname string) (domainname string) {
	i := strings.Index(hostname, ".")
	if i < 0 {
		return
	}

	return hostname[i+1:]
}

// IsRooted returns true if name ends in a '.'.
func IsRooted(name string) bool {
	return name != "" && name[len(name)-1] == '.'
}

// Labels returns a domain name labels or an Error if any.
func Labels(name string) (labels []string, err error) {
	if name == "." || len(name) == 0 {
		return []string{""}, nil
	}

	if len(name) > 255 { // RFC 3696
		return nil, fmt.Errorf("invalid name %q, len > 255", name)
	}

	for name != "" {
		i := strings.Index(name, ".")
		if i < 0 {
			if len(name) > 63 {
				return nil, fmt.Errorf("invalid label %q, len > 63", name)
			}
			labels = append(labels, name)
			return
		}

		label := name[:i]
		if len(label) > 63 {
			return nil, fmt.Errorf("invalid label %q, len > 63", label)
		}
		labels = append(labels, label)
		name = name[i+1:]
	}

	labels = append(labels, "")
	return
}

type LogLevel int

const (
	LOG_NONE   LogLevel = iota // no logging
	LOG_ERRORS                 // only error events
	LOG_EVENTS                 // + non error events
	LOG_TRACE                  // + requests & results
	LOG_DEBUG                  // everything
)

// MatchCount returns the number of labels that namea and nameb have in common
// or an Error if any. The counting starts at the root label, so any two
// valid rooted domain names have match count at least one == the root domain.
func MatchCount(namea, nameb string) (n int, err error) {
	var a, b []string
	if a, err = Labels(namea); err != nil {
		return
	}

	if b, err = Labels(nameb); err != nil {
		return
	}

	for i, j := len(a)-1, len(b)-1; i >= 0 && j >= 0 && strings.ToLower(a[i]) == strings.ToLower(b[j]); {
		n++
		i--
		j--
	}
	return
}

// Rooted name enforces name to end with a ".".
func RootedName(name string) string {
	if IsRooted(name) {
		return name
	}

	return name + "."
}

// Seconds2String converts epoch seconds to a string with the YYYYMMDDHHmmSS format.
func Seconds2String(epochSecs int64) string {
	return time.SecondsToUTC(int64(epochSecs)).Format(timeLayout)
}

// String2Seconds converts s to epoch seconds. Input string s must be in the YYYYMMDDHHmmSS format
// or a plain unsigned decadic number < 2^32.
func String2Seconds(s string) (secs int64, err error) {
	if len(s) > 10 { // human readable format
		var t *time.Time
		t, err = time.Parse(timeLayout, s)
		if err == nil {
			secs = t.Seconds()
		}
		return
	}

	// plain
	secs, err = strconv.Atoi64(s)
	if err == nil && (secs < 0 || secs >= math.MaxUint32) {
		err = fmt.Errorf("invalid time %q", s)
	}
	return
}

// RevLookupName returns a domain name for the DNS reverse lookup or "" if ip is not a valid IP address.
func RevLookupName(ip net.IP) string {
	if x := ip.To4(); x != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", x[3], x[2], x[1], x[0])
	}

	if x := ip.To16(); x != nil {
		return fmt.Sprintf(
			"%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.ip6.arpa.",
			x[15]&15,
			x[15]>>4,
			x[14]&15,
			x[14]>>4,
			x[13]&15,
			x[13]>>4,
			x[12]&15,
			x[12]>>4,

			x[11]&15,
			x[11]>>4,
			x[10]&15,
			x[10]>>4,
			x[9]&15,
			x[9]>>4,
			x[8]&15,
			x[8]>>4,

			x[7]&15,
			x[7]>>4,
			x[6]&15,
			x[6]>>4,
			x[5]&15,
			x[5]>>4,
			x[4]&15,
			x[4]>>4,

			x[3]&15,
			x[3]>>4,
			x[2]&15,
			x[2]>>4,
			x[1]&15,
			x[1]>>4,
			x[0]&15,
			x[0]>>4,
		)
	}

	return ""
}
