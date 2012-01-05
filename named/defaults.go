// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

package named

import (
	"os"
	"strings"
)

//
//
// DefaultOptions is a named.conf options statement filled with default values as defined in the Bind 9.7 ARM.
// It's used by NewOptions. $ values are expanded from environment variables with defaults taken from DefaultEnv.
var DefaultOptions = `
options {
	acache-cleaning-interval 60;
	acache-enable no;
	additional-from-auth yes;
	additional-from-cache yes;
	allow-query-cache       { localnets; localhost; };
	allow-query-cache-on    { localnets; localhost; };
	allow-update            { none; };
	allow-update-forwarding { none; };
	auth-nxdomain no;

	bindkeys-file "/etc/bind.keys";
	blackhole { none; };

	check-dup-records warn;
	check-integrity yes;
	check-mx warn;
	check-mx-cname warn;
	check-names master fail;
	check-names slave warn;
	check-names response ignore;
	check-sibling yes;
	check-srv-cname warn;
	check-wildcard yes;
	clients-per-query 10;
	coresize default;

	datasize default;
	dialup no;
	directory ".";
	dnssec-accept-expired no;
	dnssec-dnskey-kskonly no;
	dnssec-enable yes;
	dnssec-secure-to-insecure no;
	dnssec-validation yes;
	dump-file "$GODNS_dump.db";

	edns-udp-size 4096;
    empty-contact ".";
	empty-zones-enable true;

	files unlimited;
	forward first;

	heartbeat-interval 60;

	interface-interval 60;
	ixfr-from-differences no;

	lame-ttl 600;

	masterfile-format text;
	max-cache-size 0;
	max-cache-ttl 604800;
	max-clients-per-query 100;
	max-journal-size unlimited;
	max-ncache-ttl 10800;
	max-transfer-idle-in 60;
	max-transfer-idle-out 60;
	max-transfer-time-in 120;
	max-transfer-time-out 120;
	max-udp-size 4096;
	memstatistics no;
	memstatistics-file "$GODNS.memstats";
	min-roots 2;
	minimal-responses no;
	multi-master no;
	max-acache-size 16M;

	notify yes;
	notify-delay 5;

	pid-file "/var/run/godns/$GODNS.pid";
	port 53;
	preferred-glue none;

	random-device "/dev/random";
	recursing-file "$GODNS.recursing";
	recursion yes;
	recursive-clients 1000;
	reserved-sockets 512; //TODO cap
	rfc2308-type1 no;

	serial-query-rate 20;
	session-keyalg hmac-sha256;
	session-keyfile "/var/run/$GODNS/session.key";
	session-keyname "local-ddns";
	sig-signing-nodes 100;
	sig-signing-signatures 10;
	sig-signing-type 65535;
	sig-validity-interval 30;
	stacksize default;
	statistics-file "$GODNS.stats";
	statistics-interval 60;

	tcp-clients 100;
	tcp-listen-queue 3;
	topology { localhost; localnets; };
	transfer-format many-answers;
	transfers-in 10;
	transfers-out 10;
	transfers-per-ns 2;
	try-tcp-refresh yes;

	update-check-ksk yes;
	use-alt-transfer-source no; //TODO only if views are specified

	zero-no-soa-ttl yes;
	zero-no-soa-ttl-cache no;
	zone-statistics no;

};
`

// DefaultEnv supplies default values for environment variables to be substitued into DefaultOptions.
var DefaultEnv = map[string]string{
	"GODNS": "godns",
}

func defaultOptions(version string) (o *Options, err error) {
	src := DefaultOptions
	for key, val := range DefaultEnv {
		if env := os.Getenv(key); env != "" {
			val = env
		}
		src = strings.Replace(src, "$"+key, val, -1)
	}
	c := &Conf{}
	c.Options = &Options{}
	c.Options.Hostname, _ = os.Hostname()
	c.Options.Version = version
	if err = c.LoadString("default", src); err != nil {
		return
	}

	return c.Options, nil
}

func init() {
	if _, err := defaultOptions("init"); err != nil {
		panic(err)
	}
}

/*


options {
	//[ acache-cleaning-interval number; ]
	//[ acache-enable yes_or_no ; ]
	//[ additional-from-auth yes_or_no ; ]
	//[ additional-from-cache yes_or_no ; ]
	[ allow-notify { address_match_list }; ]
	[ allow-query { address_match_list }; ]
	//[ allow-query-cache { address_match_list }; ]
	//[ allow-query-cache-on { address_match_list }; ]
	[ allow-query-on { address_match_list }; ]
	//[ allow-recursion { address_match_list }; ]
	//[ allow-recursion-on { address_match_list }; ]
	[ allow-transfer { address_match_list }; ]
	[ allow-update { address_match_list }; ]
	[ allow-update-forwarding { address_match_list }; ]
	[ allow-v6-synthesis { address_match_list }; ]
	[ also-notify { ip_addr [port ip_port] ; [ ip_addr [port ip_port] ; ... ] }; ]
	[ alt-transfer-source (ip4_addr | *) [port ip_port] ; ]
	[ alt-transfer-source-v6 (ip6_addr | *) [port ip_port] ; ]
	[ auth-nxdomain yes_or_no; ]
	[ avoid-v4-udp-ports { port_list }; ]
	[ avoid-v6-udp-ports { port_list }; ]
	[ blackhole { address_match_list }; ]
	[ check-names ( master | slave | response )( warn | fail | ignore ); ]
	[ cleaning-interval number; ]
	[ clients-per-query number ; ]
	[ coresize size_spec ; ]
	[ datasize size_spec ; ]
	[ deallocate-on-exit yes_or_no; ]
	[ dialup dialup_option; ]
	[ directory path_name; ]
	[ disable-algorithms domain { algorithm; [ algorithm; ] }; ]
	[ disable-empty-zone zone_name ; ]
	[ dnssec-enable yes_or_no; ]
	[ dnssec-lookaside domain trust-anchor domain; ]
	[ dnssec-must-be-secure domain yes_or_no; ]
	[ dual-stack-servers [port ip_port] { ( domain_name [port ip_port] | ip_addr [port ip_port] ) ; ... }; ]
	[ dump-file path_name; ]
	[ edns-udp-size number; ]
	[ empty-contact name ; ]
	[ empty-server name ; ]
	[ empty-zones-enable yes_or_no ; ]
	[ fake-iquery yes_or_no; ]
	[ fetch-glue yes_or_no; ]
	[ files size_spec ; ]
	[ flush-zones-on-shutdown yes_or_no; ]
	[ forward ( only | first ); ]
	[ forwarders { [ ip_addr [port ip_port] ; ... ] }; ]
	[ has-old-clients yes_or_no; ]
	[ heartbeat-interval number; ]
	[ host-statistics yes_or_no; ]
	[ host-statistics-max number; ]
	[ hostname hostname_string; ]
	[ interface-interval number; ]
	[ key-directory path_name; ]
	[ lame-ttl number; ]
	[ listen-on [ port ip_port ] { address_match_list }; ]
	[ listen-on-v6 [ port ip_port ] { address_match_list }; ]
	[ maintain-ixfr-base yes_or_no; ]
	[ masterfile-format (text|raw) ; ]
	[ match-mapped-addresses yes_or_no; ]
	[ max-acache-size size_spec ; ]
	[ max-cache-size size_spec ; ]
	[ max-cache-ttl number; ]
	[ max-clients-per-query number ; ]
	[ max-ixfr-log-size number; ]
	[ max-journal-size size_spec; ]
	[ max-ncache-ttl number; ]
	[ max-refresh-time number ; ]
	[ max-retry-time number ; ]
	[ max-transfer-idle-in number; ]
	[ max-transfer-idle-out number; ]
	[ max-transfer-time-in number; ]
	[ max-transfer-time-out number; ]
	[ memstatistics-file path_name; ]
	[ min-refresh-time number ; ]
	[ min-retry-time number ; ]
	[ min-roots number; ]
	[ minimal-responses yes_or_no; ]
	[ multiple-cnames yes_or_no; ]
	[ named-xfer path_name; ]
	[ notify yes_or_no | explicit; ]
	[ notify-delay seconds ; ]
	[ notify-source (ip4_addr | *) [port ip_port] ; ]
	[ notify-source-v6 (ip6_addr | *) [port ip_port] ; ]
	[ pid-file path_name; ]
	[ port ip_port; ]
	[ preferred-glue ( A | AAAA | NONE ); ]
	[ provide-ixfr yes_or_no; ]
	[ query-source [ address ( ip_addr | * ) ] [ port ( ip_port | * ) ]; ]
	[ query-source-v6 [ address ( ip_addr | * ) ] [ port ( ip_port | * ) ]; ]
	[ querylog yes_or_no ; ]
	[ random-device path_name ; ]
	[ recursion yes_or_no; ]
	[ recursive-clients number; ]
	[ request-ixfr yes_or_no; ]
	[ rfc2308-type1 yes_or_no; ]
	[ root-delegation-only [ exclude { namelist } ] ; ]
	[ rrset-order { order_spec ; [ order_spec ; ... ] ] };
	[ serial-queries number; ]
	[ serial-query-rate number; ]
	[ server-id server_id_string; ]
	[ sig-signing-nodes number ; ]
	[ sig-signing-signatures number ; ]
	[ sig-signing-type number ; ]
	[ sig-validity-interval number [number]; ]
	[ sortlist { address_match_list }];
	[ stacksize size_spec ; ]
	[ statistics-file path_name; ]
	[ statistics-interval number; ]
	[ tcp-clients number; ]
	[ tcp-listen-queue number; ]
	[ tkey-dhkey key_name key_tag; ]
	[ tkey-domain domainname; ]
	[ topology { address_match_list }];
	[ transfer-format ( one-answer | many-answers ); ]
	[ transfer-source (ip4_addr | *) [port ip_port] ; ]
	[ transfer-source-v6 (ip6_addr | *) [port ip_port] ; ]
	[ transfers-in  number; ]
	[ transfers-out number; ]
	[ transfers-per-ns number; ]
	[ treat-cr-as-space yes_or_no ; ]
	[ use-alt-transfer-source yes_or_no; ]
	[ use-id-pool yes_or_no; ]
	[ use-ixfr yes_or_no ; ]
	[ version version_string; ]
	[ zone-statistics yes_or_no; ]
};

*/
