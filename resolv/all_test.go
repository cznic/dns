// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz


package resolv

import (
	"testing"
)

func Test0(t *testing.T) {
	const src = `

nameserver 1.2.3.4 	 	
 	 	
# parser test
#
# domain X
# abc
# 
nameserver	5.6.7.8 	 		 	

nameserver 2001:1488:ac14:1400:1aa9:5ff:fef6:7315 	 	

search s1.x-y.y 	 	
 	 	
domain a.domain.test 	 	

search 	 	s2.a.b s3 s4 s5 s6 	 	

sortlist 130.155.0.0 	 	130.155.160.0/255.255.240.0 131.155.160.0/255.255.241.0 	 	

sortlist 	 	132.155.160.0/255.255.242.0 	 	

options debug rotate no-check-names inet6 ip6-bytestring ip6-dotint no-ip6-dotint edns0 ndots 	 	: 	 	2 timeout :	6 	attempts:3 	 	

#`

	c := NewConf()
	if err := c.LoadString("Test0", src); err != nil {
		t.Fatal(10, err)
	}

	t.Log(c)
}
