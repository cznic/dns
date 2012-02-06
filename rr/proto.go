// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

package rr

// IP_Protocol is a IP protocol number. Used by WKS RR. See e.g.
// http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
type IP_Protocol byte

// Values of IP_Protocol
const (
	TCP_Protocol IP_Protocol = 6  // Transmission Control Protocol
	UDP_Protocol IP_Protocol = 17 // User Datagram Protocol
)

// Text values of IP_Protocol
var IP_Protocols = map[IP_Protocol]string{
	TCP_Protocol: "TCP",
	UDP_Protocol: "UDP",
}
