// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

package named

import (
	"testing"
)

func Test0(t *testing.T) {
	c, err := NewConf("TEST")
	if err != nil {
		t.Fatal(10, err)
	}

	t.Log(c)
}

func Test1(t *testing.T) {
	c, err := NewConf("TEST")
	if err != nil {
		t.Fatal(10, err)
	}

	if err = c.LoadString("Test1", `
// This is the primary configuration file for the BIND DNS server named.
//
// Please read /usr/share/doc/bind9/README.Debian.gz for information on the 
// structure of BIND configuration files in Debian, *BEFORE* you customize 
// this configuration file.
//
// If you are just adding zones, please do that in /etc/bind/named.conf.local

#include "/etc/bind/named.conf.options";
masters "m1" { "m2"; };
masters "m2" port 3 { "m3"; };
masters "m3" { "m4"; "m5"; };
masters "m4" { 1.2.3.4; ::1; "m6"; 2.3.4.5 port 5432; 3.4.5.6 key "K"; };
masters "m5" { 5.5.5.5; };
masters "m6" { ::6; };
options {
	directory "/var/cache/bind";

	// If there is a firewall between you and nameservers you want
	// to talk to, you may need to fix the firewall to allow multiple
	// ports to talk.  See http://www.kb.cert.org/vuls/id/800113

	// If your ISP provided one or more IP addresses for stable 
	// nameservers, you probably want to use them as forwarders.  
	// Uncomment the following block, and insert the addresses replacing 
	// the all-0's placeholder.

	// forwarders {
	// 	0.0.0.0;
	// };

	auth-nxdomain no;    # conform to RFC1035
	listen-on port 1234 { any; };
	listen-on port 5678 { any; };
	listen-on-v6 port 9012 {any;};
	listen-on-v6 { any; };

	forwarders {
		  # Replace the address below with the address of your provider's DNS server
		  194.0.12.1;
	};
};

#include "/etc/bind/named.conf.local";
//
// Do any local configuration here
//

// Consider adding the 1918 zones here, if they are not used in your
// organization
//include "/etc/bind/zones.rfc1918";

# This is the zone definition. replace example.com with your domain name
zone "nic.cz" {
        type master;
        file "/etc/bind/zones/nic.cz.db";
        };

# This is the zone definition for reverse DNS. replace 0.168.192 with your network address in reverse notation - e.g my network address is 192.168.0
zone "215.20.20.172.in-addr.arpa" {
     type master;
     file "/etc/bind/zones/rev.20.20.172.in-addr.arpa";
};

#include "/etc/bind/named.conf.default-zones";
// prime the server with knowledge of the root servers
zone "." {
	type hint;
	file "/etc/bind/db.root";
};

// be authoritative for the localhost forward and reverse zones, and for
// broadcast zones as per RFC 1912

zone "localhost" {
	type master;
	file "/etc/bind/db.local";
};

zone "127.in-addr.arpa" {
	type master;
	file "/etc/bind/db.127";
};

zone "0.in-addr.arpa" {
	type master;
	file "/etc/bind/db.0";
};

zone "255.in-addr.arpa" {
	type master;
	file "/etc/bind/db.255";
};
	`); err != nil {
		t.Fatal(20, err)
	}

	t.Log(c)
}
