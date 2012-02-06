// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

package rr

// IP_Port is a IP port number. Used by WKS. See e.g.
// http://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
type IP_Port int

// Values of IP_Port
const (
	SMTP_Port IP_Port = 25 // Simple Mail Transfer Protocol
	DNS_Port  IP_Port = 53 // Domain Name System
)

// Text values of IP_Port
var IP_Ports = map[IP_Port]string{
	DNS_Port:  "DNS",
	SMTP_Port: "SMTP",
}
