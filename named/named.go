// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

// WIP: Package named supports named.conf formatted data (see also `man named.conf`).
// Supported are conversions from a file or string to an internal representation and back to a string.
// Documentation comments in this package are often excerpts from the BIND 9.7 ARM 
// available at http://www.isc.org/files/arm97.pdf. See also the LICENSE-BIND file.
package named

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/cznic/dns/rr"
	"github.com/cznic/strutil"
	"io/ioutil"
	"net"
	"strings"
)

// System named.conf name
var Sys = "/etc/bind/named.conf" //TODO:LSB only

type formatter interface {
	str(f strutil.Formatter)
}

//TODO +err/panic
//TODO f.Format -> w/ checks/panic?
func str(f formatter) string {
	b := bytes.NewBuffer(nil)
	f.str(strutil.IndentFormatter(b, "\t"))
	return b.String()
}

// AclName* constants are the values of the AclName.Type tag
const (
	AclNameAny AclNameType = iota
	AclNameNone
	AclNameLocalhost
	AclNameLocalnets
	AclNameDomainName
)

// AclNameType is the type of the AclName.Type tag
type AclNameType int

// AclName holds the name of an address match list as defined by the acl statement.
type AclName struct {
	Type       AclNameType
	DomainName string
}

// NewAclName creates a new AclName from the typ and name arguments.
func NewAclName(typ AclNameType, name string) *AclName {
	return &AclName{typ, name}
}

func (x *AclName) str(f strutil.Formatter) {
	switch x.Type {
	default:
		panic(fmt.Errorf("unexpected AclNameType %d", x.Type))
	case AclNameAny:
		f.Format("any")
	case AclNameNone:
		f.Format("none")
	case AclNameLocalhost:
		f.Format("localhost")
	case AclNameLocalnets:
		f.Format("localnets")
	case AclNameDomainName:
		f.Format("%q", x.DomainName)
	}
}

func (x *AclName) String() string {
	return str(x)
}

// Elements can be negated with a leading exclamation mark (‘!’), and the match list names ”any”, ”none”,
// ”localhost”, and ”localnets” are predefined. More information on those names can be found in the
// description of the acl statement.
type AddressMatchListElement struct {
	Neg  bool
	Item interface{}
}

func (x *AddressMatchListElement) str(f strutil.Formatter) {
	if x.Neg {
		f.Format("! ")
	}
	x.Item.(formatter).str(f)
}

func (x *AddressMatchListElement) String() string {
	return str(x)
}

// Address match lists are primarily used to determine access control for various server operations. They
// are also used in the listen-on and sortlist statements. The elements which constitute an address match
// list can be any of the following:
//	• an IP address (IPv4 or IPv6)
//	• an IP prefix (in ‘/’ notation)
//	• a key ID, as defined by the key statement
//	• the name of an address match list defined with the acl statement
//	• a nested address match list enclosed in braces
type AddressMatchList []AddressMatchListElement

func (x *AddressMatchList) str(f strutil.Formatter) {
	for _, item := range *x {
		item.str(f)
		f.Format(";\n")
	}
}

func (x *AddressMatchList) String() string {
	return str(x)
}

// A Conf holds the data found in a Internet domain name server configuration file,
// e.g. '/etc/bind/named.conf'. See also named.conf(5).
// The implementation is based on BIND 9.7 ARM available at http://www.isc.org/files/arm97.pdf
type Conf struct {
	ManagedKeys ManagedKeys
	Masters     []Masters
	Options     *Options
	Zones       Zones
} //TODO:Complete full specs

// NewConf create an empty Conf ready to use or an Error if any.
// The Options.Version field is filled from the version parameter.
func NewConf(version string) (c *Conf, err error) {
	c = &Conf{}
	c.Options, err = NewOptions(version)
	return
}

func (x *Conf) str(f strutil.Formatter) {
	x.ManagedKeys.str(f)
	for _, v := range x.Masters {
		v.str(f)
	}
	x.Options.str(f)
	x.Zones.str(f)
}

func (x *Conf) String() string {
	return str(x)
}

// Load Conf from a named.conf format string s. Return an Error, if any.
func (c *Conf) LoadString(fname, s string) (err error) {
	lx := c.newLex(fname, strings.NewReader(s))

	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%s:%d:%d - %s", lx.name, lx.line, lx.column, e.(error))
		}
	}()

	if yyParse(lx) != 0 {
		panic(errors.New("syntax error"))
	}

	*c = *lx.conf
	return
}

// Load Conf from a configuration file fname. Return an Error, if any.
func (c *Conf) Load(fname string) (err error) {
	defer func() {
		if e := recover(); e != nil {
			err = e.(error)
		}
	}()

	buf, err := ioutil.ReadFile(fname)
	if err != nil {
		panic(err)
	}

	return c.LoadString(fname, string(buf))
}

// IPAndPort packs an IP address with an optional port number.
type IPAndPort struct {
	IP   net.IP  // Specifies the IP address.
	Port *IPPort // Optional port number or nil.
}

func (x *IPAndPort) str(f strutil.Formatter) {
	if x.IP != nil {
		f.Format("%s", x.IP)
	} else {
		f.Format("*")
	}
	if x.Port != nil {
		f.Format(" port %d", *x.Port)
	}
}

func (x *IPAndPort) String() string {
	return str(x)
}

// IPs is a slice of IPAndPort
type IPs []IPAndPort

func (x IPs) str(f strutil.Formatter) {
	for _, item := range x {
		item.str(f)
		f.Format(";\n")
	}
}

func (x IPs) String() string {
	return str(x)
}

// IPPort is the type of an IP port number. The number is limited to 0 through 65535,
// with values below 1024 typically restricted to use by processes
// running as root. In some cases, an asterisk (‘*’) character can
// be used as a placeholder to select a random high-numbered
// port. This is by convention indicated by *IPPort == nil.
type IPPort uint16

// NewIPPort creates a new unique instance of port and returns a pointer to it.
func NewIPPort(port IPPort) *IPPort {
	x := new(IPPort)
	*x = port
	return x
}

// The listen-on option is used to specify the interfaces and the ports on which the server will listen for
// incoming queries.
type ListenOn struct {
	Port             *IPPort
	AddressMatchList AddressMatchList
}

func (x *ListenOn) str(f strutil.Formatter) {
	if x.Port != nil {
		f.Format(" port %d", *x.Port)
	}
	f.Format(" {%i\n")
	x.AddressMatchList.str(f)
	f.Format("%u};\n")
}

func (x *ListenOn) String() string {
	return str(x)
}

// ManagedKey is an item of ManagedKeys
type ManagedKey struct {
	Name string
	*rr.DNSKEY
}

// NewManagedKey returns a newly constructed ManagedKey
func NewManagedKey(Name string, key *rr.DNSKEY) *ManagedKey {
	return &ManagedKey{Name, key}
}

func (k *ManagedKey) str(f strutil.Formatter) {
	f.Format("%q initial-key %d %d %d\n\"%s\";\n", k.Name, k.Flags, k.Protocol, k.Algorithm, strutil.Base64Encode(k.Key))
}

func (x *ManagedKey) String() string {
	return str(x)
}

// ManagedKeys holds the data from the managed-keys statements
type ManagedKeys []*ManagedKey

func (k ManagedKeys) str(f strutil.Formatter) {
	if len(k) == 0 {
		return
	}

	f.Format("managed-keys {%i\n")
	for _, key := range k {
		key.str(f)
	}
	f.Format("%u};\n")
}

func (x *ManagedKeys) String() string {
	return str(x)
}

// SessionKeyAlg is the type of Options.SessionKeyAlg field.
type SessionKeyAlg int

// Values of SessionKeyAlg
const (
	SessionKeyAlg_HMAC_MD5 SessionKeyAlg = iota
	SessionKeyAlg_HMAC_SHA1
	SessionKeyAlg_HMAC_SHA224
	SessionKeyAlg_HMAC_SHA256
	SessionKeyAlg_HMAC_SHA384
	SessionKeyAlg_HMAC_SHA512
)

var sessionKeyAlgStr = map[SessionKeyAlg]string{
	SessionKeyAlg_HMAC_MD5:    "hmac-md5",
	SessionKeyAlg_HMAC_SHA1:   "hmac-sha1",
	SessionKeyAlg_HMAC_SHA224: "hmac-sha224",
	SessionKeyAlg_HMAC_SHA256: "hmac-sha256",
	SessionKeyAlg_HMAC_SHA384: "hmac-sha384",
	SessionKeyAlg_HMAC_SHA512: "hmac-sha512",
}

func (k SessionKeyAlg) str(f strutil.Formatter) {
	f.Format("%s", sessionKeyAlgStr[k])
}

func (x SessionKeyAlg) String() string {
	return str(x)
}

// Notify is the type of Options.Notify
type Notify int

// Values of Notify
const (
	NotifyYes Notify = iota
	NotifyMasterOnly
	NotifyExplicit
	NotifyNo
)

func (n Notify) String() string {
	return str(n)
}

func (n Notify) str(f strutil.Formatter) {
	switch n {
	case NotifyYes:
		f.Format("true")
	case NotifyMasterOnly:
		f.Format("master-only")
	case NotifyExplicit:
		f.Format("explicit")
	case NotifyNo:
		f.Format("false")
	}
}

// IxfrFromDiffs is the type of Options.IxfFromDiffs
type IxfrFromDiffs int

// Values of IxfrFromDiffs
const (
	IxfrFromDiffsYes IxfrFromDiffs = iota
	IxfrFromDiffsMaster
	IxfrFromDiffsSlave
	IxfrFromDiffsNo
)

func (i IxfrFromDiffs) String() string {
	return str(i)
}

func (i IxfrFromDiffs) str(f strutil.Formatter) {
	switch i {
	case IxfrFromDiffsYes:
		f.Format("true")
	case IxfrFromDiffsMaster:
		f.Format("master")
	case IxfrFromDiffsSlave:
		f.Format("slave")
	case IxfrFromDiffsNo:
		f.Format("false")
	}
}

// WarnFailIgnore is the type of several problem behaviour options, e.g. Options.CheckDupRecs.
type WarnFailIgnore int

// Values of WarnFailIgnore
const (
	WarnFailIgnore_Warn WarnFailIgnore = iota
	WarnFailIgnore_Ignore
	WarnFailIgnore_Fail
)

func (w WarnFailIgnore) String() string {
	return str(w)
}

func (w WarnFailIgnore) str(f strutil.Formatter) {
	switch w {
	case WarnFailIgnore_Warn:
		f.Format("warn")
	case WarnFailIgnore_Ignore:
		f.Format("ignore")
	case WarnFailIgnore_Fail:
		f.Format("fail")
	}
}

// Forward is the type of Options.Forward
type Forward int

// Values of Forward
const (
	ForwardFirst Forward = iota
	ForwardOnly
)

func (fwd Forward) String() string {
	return str(fwd)
}

func (fwd Forward) str(f strutil.Formatter) {
	switch fwd {
	case ForwardFirst:
		f.Format("first")
	case ForwardOnly:
		f.Format("only")
	}
}

// TransferFormat is the type of Options.TransferFormat
type TransferFormat int

// Values of TransferFormat
const (
	TransferFormatOneAnswer TransferFormat = iota
	TransferFormatManyAnswers
)

func (t TransferFormat) String() string {
	return str(t)
}

func (t TransferFormat) str(f strutil.Formatter) {
	switch t {
	case TransferFormatOneAnswer:
		f.Format("one-answer")
	case TransferFormatManyAnswers:
		f.Format("many-answers")
	}
}

// SizeSpec is the type of some of the Options fields, e.g. Coresize.
type SizeSpec int64

// Special SizeSpec values. All of them are negative.
const (
	SizeSpecDefault   SizeSpec = -1
	SizeSpecUnlimited SizeSpec = -2
)

func (s SizeSpec) String() string {
	return str(s)
}

func (s SizeSpec) str(f strutil.Formatter) {
	switch s {
	default:
		f.Format("%d", uint64(s))
	case SizeSpecDefault:
		f.Format("default")
	case SizeSpecUnlimited:
		f.Format("unlimited")
	}
}

// MasterFileFormat is the type of Options.MasterFileFormat
type MasterFileFormat int

// Values of MasterFileFormat
const (
	MasterFileFormatText MasterFileFormat = iota
	MasterFileFormatRaw
)

func (m MasterFileFormat) String() string {
	return str(m)
}

func (m MasterFileFormat) str(f strutil.Formatter) {
	switch m {
	case MasterFileFormatText:
		f.Format("text")
	case MasterFileFormatRaw:
		f.Format("raw")
	}
}

// PortList is a list of port number pairs. Each pair represents a range of ports.
type PortList []uint16

func (p PortList) String() string {
	return str(p)
}

func (p PortList) str(f strutil.Formatter) {
	for i := 0; i < len(p); i += 2 {
		from := p[i]
		to := from
		if i+1 < len(p) {
			to = p[i+1]
		}
		if from == to {
			f.Format(" %d;", from)
			continue
		}

		f.Format(" range %d %d;", from, to)
	}
}

// DialupOption is the type of e.g. Options.Dialup
type DialupOption int

// Values of DialupOption
const (
	DialupNo DialupOption = iota
	DialupYes
	DialupNotify
	DialupNotifyPassive
	DialupRefresh
	DialupPassive
)

func (d DialupOption) String() string {
	return str(d)
}

func (d DialupOption) str(f strutil.Formatter) {
	switch d {
	case DialupNo:
		f.Format("no")
	case DialupYes:
		f.Format("yes")
	case DialupNotify:
		f.Format("notify")
	case DialupNotifyPassive:
		f.Format("notify-passive")
	case DialupRefresh:
		f.Format("refresh")
	case DialupPassive:
		f.Format("passive")
	}
}

// DisabledAlgorithms is the type of e.g. Options.DisableAlgorithms.
type DisabledAlgorithms struct {
	Domain     string
	Algorithms []SessionKeyAlg
}

func (d DisabledAlgorithms) String() string {
	return str(d)
}

func (d DisabledAlgorithms) str(f strutil.Formatter) {
	f.Format("%q {%i\n", d.Domain)
	for _, alg := range d.Algorithms {
		f.Format("%s;\n", alg)
	}
	f.Format("%u\n};\n")
}

// DNSSecDelegation is the type of e.g. Options.DNSSecLookaside.
type DNSSecDelegation struct {
	Domain, Delegation string
}

func (d DNSSecDelegation) Auto() bool {
	return d.Domain == ""
}

func (d DNSSecDelegation) String() string {
	return str(d)
}

func (d DNSSecDelegation) str(f strutil.Formatter) {
	if d.Auto() {
		f.Format("auto")
		return
	}

	f.Format("%q trusted-anchor %q", d.Domain, d.Delegation)
}

// DNSSecMustBeSecured is the type of e.g. Options.DNSSecMustBeSecure
type DNSSecMustBeSecured struct {
	Domain string
	Yes    bool
}

func (d DNSSecMustBeSecured) String() string {
	return str(d)
}

func (d DNSSecMustBeSecured) str(f strutil.Formatter) {
	f.Format("%q %t", d.Domain, d.Yes)
}

// DualStackServer is the type of DualStackServers.Servers.
// Either Domain of Addr must be non empty but not both.
type DualStackServer struct {
	Domain string
	Addr   net.IP
	Port   *IPPort
}

func (d DualStackServer) String() string {
	return str(d)
}

func (d DualStackServer) str(f strutil.Formatter) {
	switch {
	case d.Domain != "":
		f.Format("%q", d.Domain)
	case len(d.Addr) != 0:
		f.Format("%s", d.Addr)
	}
	if d.Port != nil {
		f.Format(" port %d", *d.Port)
	}
	f.Format(";\n")
}

// DualStackServers is the type of e.g. Options.DualStackServers
type DualStackServers struct {
	Port    *IPPort
	Servers []DualStackServer
}

func (d DualStackServers) String() string {
	return str(d)
}

func (d DualStackServers) str(f strutil.Formatter) {
	if len(d.Servers) == 0 {
		return
	}

	f.Format("dual-stack-servers")
	if d.Port != nil {
		f.Format(" port %d", *d.Port)
	}
	f.Format(" {%i\n")
	for _, x := range d.Servers {
		x.str(f)
	}
	f.Format("%u};\n")
}

// Ordering is the type of ordering in e.g. OrderSpec.Order
type Ordering int

// Values of Ordering
const (
	OrderingFixed Ordering = iota
	OrderingRandom
	OrderingCyclic
)

func (o Ordering) String() string {
	return str(o)
}

func (o Ordering) str(f strutil.Formatter) {
	switch o {
	case OrderingFixed:
		f.Format("fixed")
	case OrderingRandom:
		f.Format("random")
	case OrderingCyclic:
		f.Format("cyclic")
	}
}

// OrderSpec is the type of e.g. Options.RRSetOrder.OrderSpecs
type OrderSpec struct {
	Class *ZoneClass
	Type  *rr.Type
	Name  *string
	Order Ordering
}

func (o *OrderSpec) String() string {
	return str(o)
}

func (o *OrderSpec) str(f strutil.Formatter) {
	if o.Class != nil {
		f.Format("class %s ", *o.Class)
	}
	if o.Type != nil {
		f.Format("type %s ", *o.Type)
	}
	if o.Name != nil {
		f.Format("name %q ", *o.Name)
	}
	f.Format("order %s", o.Order)
}

// The options statement sets up global options to be used by e.g. BIND. This statement may appear only once
// in a configuration file. If there is no options statement, an options block with each option set to its
// default will be used.
type Options struct {
	ACacheCleaningInterval int  // The server will remove stale cache entries, based on an LRU based algorithm, every acache-cleaning-interval minutes.
	ACacheEnable           bool // If yes, additional section caching is enabled.

	// These options control the behavior of an authoritative
	// server when answering queries which have additional data, or when following CNAME and 
	// DNAME chains.
	AdditionalFromAuth  bool
	AdditionalFromCache bool

	AllowNotify           AddressMatchList      // Specifies which hosts are allowed to notify this server, a slave, of zone changes in addition to the zone masters.
	AllowQuery            AddressMatchList      // Specifies which hosts are allowed to ask ordinary DNS questions.
	AllowQueryOn          AddressMatchList      // Specifies which local addresses can accept ordinary DNS questions.
	AllowQueryCache       AddressMatchList      // Specifies which hosts are allowed to get answers from the cache.
	AllowQueryCacheOn     AddressMatchList      // Specifies which local addresses can give answers from the cache. 
	AllowRecursion        AddressMatchList      // Specifies which hosts are allowed to make recursive queries through this server.
	AllowRecursionOn      AddressMatchList      // Specifies which local addresses can accept recursive queries.
	AllowTransfer         AddressMatchList      // Specifies which hosts are allowed to receive zone transfers from the server.
	AllowUpdate           AddressMatchList      // Specifies which hosts are allowed to submit Dynamic DNS updates for master zones.
	AllowUpdateForwarding AddressMatchList      // Specifies which hosts are allowed to submit Dynamic DNS updates to slave zones to be forwarded to the master.
	AllowV6Synthesis      AddressMatchList      // (Obsolete) This option was used for the smooth transition from AAAA to A6 and from ”nibble labels” to binary labels.
	AlsoNotify            IPs                   // Defines a global list of IP addresses of name servers that are also sent NOTIFY messages whenever a fresh copy of the zone is loaded, in addition to the servers listed in the zone’s NS records.
	AltTransferSource     *IPAndPort            // An alternate transfer source if the one listed in transfer-source fails and use-alt-transfer-source is set.
	AltTransferSourceV6   *IPAndPort            // An alternate transfer source if the one listed in transfer-source-v6 fails and use-alt-transfer-source is set.
	AuthNXDomain          bool                  // If true, then the AA bit is always set on NXDOMAIN responses, even if the server is not actually authoritative.
	AvoidV4UdpPorts       PortList              // Prevent a name server from choosing as its random source port a port that is blocked by your firewall or a port that is used by other applications.
	AvoidV6UdpPorts       PortList              // See AvoidV4UdpPorts
	BindKeysFile          string                // The pathname of a file to override the built-in trusted keys provided by the server.
	Blackhole             AddressMatchList      // Specifies a list of addresses that the server will not accept queries from or use to resolve a query.
	CheckDupRecs          WarnFailIgnore        // Check master zones for records that are treated as different by DNSSEC but are semantically equal in plain DNS.
	CheckIntegrity        bool                  // Perform post load zone integrity checks on master zones.
	CheckMx               WarnFailIgnore        // Check whether the MX record appears to refer to a IP address.
	CheckMxCname          WarnFailIgnore        // If check-integrity is set then fail, warn or ignore MX records that refer to CNAMES.
	CheckNamesMaster      WarnFailIgnore        // This option is used to restrict the character set and syntax of certain domain names in master files.
	CheckNamesSlave       WarnFailIgnore        // This option is used to restrict the character set and syntax of certain domain names in slave files.
	CheckNamesResponse    WarnFailIgnore        // This option is used to restrict the character set and syntax of certain domain names in DNS responses received from the network.
	CheckSibling          bool                  // When performing integrity checks, also check that sibling glue exists.
	CheckSrvCname         WarnFailIgnore        // If check-integrity is set then fail, warn or ignore SRV records that refer to CNAMES.
	CheckWildcard         bool                  // This option is used to check for non-terminal wildcards.
	CleaningInterval      int                   // This interval is effectively obsolete.
	ClientsPerQuery       int                   // The initial number of recursive simultaneous clients for any given query (<qname,qtype,qclass>) that the server will accept before dropping additional clients.
	Coresize              SizeSpec              // The maximum size of a core dump.
	Datasize              SizeSpec              // The maximum amount of data memory the server may use. 
	DeallocateOnExit      bool                  // This option was used in e.g. BIND 8 to enable checking for memory leaks on exit.
	Dialup                DialupOption          // If yes, then the server treats all zones as if they are doing zone transfers across a dial-on-deman dialup link, which can be brought up by traffic originating from this server.
	Directory             string                // The working directory of the server.
	DisableAlgorithms     []DisabledAlgorithms  // Disable the specified DNSSEC algorithms at and below the specified name. 
	DisableEmptyZone      []string              // Disable individual empty zones.
	DNSSecAcceptExpired   bool                  // Accept expired signatures when verifying DNSSEC signatures.
	DNSSecDnsKeyKskOnly   bool                  // When this option and update-check-ksk are both set to yes, only key-signing keys (that is, keys with the KSK bit set) will be used to sign the DNSKEY RRset at the zone apex.
	DNSSecEnable          bool                  // Enable DNSSEC support in named. Unless set to yes, named behaves as if it does not support DNSSEC. 
	DNSSecLookaside       []DNSSecDelegation    // When set, dnssec-lookaside provides the validator with an alternate method to validate DNSKEY records at the top of a zone.
	DNSSecMustBeSecure    []DNSSecMustBeSecured // Specify hierarchies which must be or may not be secure (signed and validated).
	DNSSecSecure2Insecure bool                  // Allow a dynamic zone to transition from secure to insecure (i.e., signed to unsigned) by deleting all of the DNSKEY records.
	DNSSecValidation      bool                  // Enable DNSSEC validation in named. Note dnssec-enable also needs to be set to yes to be effective.
	DualStackServers      DualStackServers      // Specifies host names or addresses of machines with access to both IPv4 and IPv6 transports.
	DumpFile              string                // The pathname of the file the server dumps the database to when instructed to do so.
	EdnsUdpSize           int                   // Sets the advertised EDNS UDP buffer size in bytes to control the size of packets received.
	EmptyContact          string                // Specify what contact name will appear in the returned SOA record for empty zones.
	EmptyServer           string                // Specify what server name will appear in the returned SOA record for empty zones.
	EmptyZonesEnable      bool                  // Enable or disable all empty zones.
	FakeIQuery            bool                  // (Obsolete) In BIND 8, this option enabled simulating the obsolete DNS query type IQUERY.
	FetchGlue             bool                  // (Obsolete) In BIND 8, fetch-glue yes caused the server to attempt to fetch glue resource records it didn’t have when constructing the additional data section of a response.
	Files                 SizeSpec              // The maximum number of files the server may have open concurrently.
	FlushZonesOnShutdown  bool                  // When the nameserver exits due receiving SIGTERM, flush or do not flush any pending zone writes.

	// This option is only meaningful if the forwarders list is not empty. A value of first, the
	// default, causes the server to query the forwarders first — and if that doesn’t answer the question,
	// the server will then look for the answer itself. If only is specified, the server will only query the
	// forwarders.
	Forward Forward

	// The forwarding facility can be used to create a large site-wide cache on a few servers, reducing traffic
	// over links to external name servers. It can also be used to allow queries by servers that do not have
	// direct access to the Internet, but wish to look up exterior names anyway. Forwarding occurs only on
	// those queries for which the server is not authoritative and does not have the answer in its cache.
	Forwarders IPs

	// This option was incorrectly implemented in BIND 8, and is ignored by BIND 9. To
	// achieve the intended effect of has-old-clients yes, specify the two separate options auth-nxdomain
	// yes and rfc2308-type1 no instead.
	HasOldClients bool

	HeartbeatInterval int    // The server will perform zone maintenance tasks for all zones marked as dialup whenever this interval expires.
	Hostname          string // The hostname the server should report via a query of the name hostname.bind with type TXT, class CHAOS.
	HostStatistics    bool   // (Obsolete) In BIND 8, this enables keeping of statistics for every host that the name server interacts with. Not implemented in BIND 9.
	HostStatisticsMax uint64 // (Obsolete) In BIND 8, specifies the maximum number of host statistics entries to be kept. Not implemented in BIND 9.
	InterfaceInterval int    // The server will scan the network interface list every interface-interval minutes.

	// When yes and the server loads a new version of a master zone from its zone
	// file or receives a new version of a slave file by a non-incremental zone transfer, it will compare
	// the new version to the previous one and calculate a set of differences.
	IxfrFromDiffs IxfrFromDiffs

	KeyDirectory         string // When performing dynamic update of secure zones, the directory where the public and private DNSSEC key files should be found, if different than the current working directory.
	LameTtl              int    // Sets the number of seconds to cache a lame server indication. 0 disables caching.
	ListenOn             []ListenOn
	ListenOnV6           []ListenOn
	MaintainIxfrBase     bool             // (Obsolete) It was used in BIND 8 to determine whether a transaction log was kept for Incremental Zone Transfer.
	MasterFileFormat     MasterFileFormat // Specifies the file format of zone files.
	MatchMappedAddresses bool             // (Obsolete) If yes, then an IPv4-mapped IPv6 address will match any address match list entries that match the corresponding IPv4 address.
	MaxACacheSize        SizeSpec         // The maximum amount of memory in bytes to use for the server’s acache.
	MaxCacheSize         SizeSpec         // The maximum amount of memory to use for the server’s cache, in bytes.
	MaxCacheTtl          int              // Sets the maximum time for which the server will cache ordinary (positive) answers. 
	MaxIxfrLogSize       uint64           // (Obsolete) Accepted and ignored for BIND 8 compatibility. The option max-journal-size performs a similar function in BIND 9.
	MaxJournalSize       SizeSpec         // Sets a maximum size for each journal file.
	MaxClientsPerQuery   int              // The maximum number of recursive simultaneous clients for any given query (<qname,qtype,qclass>) that the server will accept before dropping additional clients.
	MaxNCacheTtl         int              // To reduce network traffic and increase performance, the server stores negative answers. max-ncache-ttl is used to set a maximum retention time for these answers in the server in seconds.
	MaxUdpSize           int              // Sets the maximum EDNS UDP message size named will send in bytes.
	MaxXferIdleIn        int              // Inbound zone transfers making no progress in this many minutes will be terminated.
	MaxXferIdleOut       int              // Outbound zone transfers making no progress in this many minutes will be terminated.
	MaxXferTimeIn        int              // Inbound zone transfers running longer than this many minutes will be terminated.
	MaxXferTimeOut       int              // Outbound zone transfers running longer than this many minutes will be terminated.
	MemStats             bool             // Write memory statistics to the file specified by memstatistics-file at exit.
	MemStatsFile         string           // The pathname of the file the server writes memory usage statistics to on exit.
	MinimalResponses     bool             // If yes, then when generating responses the server will only add records to the authority and additional data sections when they are required (e.g. delegations, negative responses).

	// These options control the server’s behavior on refreshing a zone (querying for SOA changes)
	// or retrying failed transfers. Usually the SOA values for the zone are used, but these values
	// are set by the master, giving slave server administrators little control over their contents.
	MinRefreshTime uint64
	MinRetryTime   uint64
	MaxRefreshTime uint64
	MaxRetryTime   uint64

	MinRoots           int         // The minimum number of root servers that is required for a request for the root servers to be accepted.
	MultiMaster        bool        // This should be set when you have multiple masters for a zone and the addresses refer to different machines.
	MultipleCnames     bool        // (Obsolete) This option was used in BIND 8 to allow a domain name to have multiple CNAME records in violation of the DNS standards.
	NamedXfer          string      // (Obsolete) Used in BIND 8 to specify the pathname to the named-xfer program.
	Notify             Notify      // If yes (the default), DNS NOTIFY messages are sent when a zone the server is authoritative for changes.
	NotifyDelay        int         // The delay, in seconds, between sending sets of notify messages for a zone.
	NotifySource       *IPAndPort  // Determines which local source address, and optionally UDP port, will be used to send NOTIFY messages.
	NotifySourceV6     *IPAndPort  // Like notify-source, but applies to notify messages sent to IPv6 addresses.
	NotifyToSoa        bool        // If yes do not check the nameservers in the NS RRset against the SOA MNAME. Normally a NOTIFY message is not sent to the SOA MNAME (SOA ORIGIN) as it is supposed to contain the name of the ultimate master.
	PIDFile            string      // The pathname of the file the server writes its process ID in.
	Port               IPPort      // The UDP/TCP port number the server uses for receiving and sending DNS protocol traffic.
	PreferredGlue      *rr.Type    // If specified, the listed type (A or AAAA) will be emitted before other glue in the additional section of a query response.
	ProvideIxfr        *bool       // etermines whether the local server, acting as master, will respond with an incremental zone transfer when the given remote server, a slave, requests it.
	Querylog           *bool       // Specify whether query logging should be started when named starts.
	QuerySource        *IPAndPort  // Specify the IPv4 source address to be used for queries sent to remote server.
	QuerySourceV6      *IPAndPort  // Specify the IPv6 source address to be used for queries sent to remote server.
	RandomDevice       string      // The source of entropy to be used by the server.
	Recursion          bool        // If yes, and a DNS query requests recursion, then the server will attempt to do all the work required to answer the query.
	RecursingFile      string      // The pathname of the file the server dumps the queries that are currently recursing when instructed to do so.
	RecursiveClients   int         // The maximum number of simultaneous recursive lookups the server will perform on behalf of clients.
	RequestIxfr        *bool       // determines whether the local server, acting as a slave, will request incremental zone transfers from the given remote server, a master.
	ReservedSockets    int         // The number of file descriptors reserved for TCP, stdio, etc.
	Rfc2308Type1       bool        // Setting this to yes will cause the server to send NS records along with the SOA record for negative answers.
	RootDelegationOnly *[]string   // Turn on enforcement of delegation-only in TLDs (top level domains) and root zones with an optional exclude list.
	RRSetOrder         []OrderSpec // Permits configuration of the ordering of the records in a multiple record response.

	// Slave servers will periodically query master servers to find out if zone serial numbers
	// have changed. Each such query uses a minute amount of the slave server’s network bandwidth.
	// To limit the amount of bandwidth used, BIND 9 limits the rate at which queries are sent. 
	SerialQueryRate int

	SerialQueries                  uint64           // (Obsolete) In BIND 8, the serial-queries option set the maximum number of concurrent serial number queries allowed to be outstanding at any given time.
	ServerId                       string           // The ID the server should report when receiving a Name Server Identifier (NSID) query, or a query of the name ID.SERVER with type TXT, class CHAOS.
	SessionKeyAlg                  SessionKeyAlg    // The algorithm to use for the TSIG session key.
	SessionKeyFile                 string           // The pathname of the file into which to write a TSIG session key.
	SessionKeyName                 string           // The key name to use for the TSIG session key.
	SigValidityIntervalBase        int              // Specifies the number of days into the future when DNSSEC signatures automatically generated as a result of dynamic updates will expire.
	SigSigningNodes                int              // Specify the maximum number of nodes to be examined in each quantum when signing a zone with a new DNSKEY.
	SigSigningSignatures           int              // Specify a threshold number of signatures that will terminate processing a quantum when signing a zone with a new DNSKEY.
	SigSigningType                 int              // Specify a private RDATA type to be used when generating key signing records.
	SigValidityIntervalExpireHours int              // Specifies how long before expiry that the signatures will be regenerated.
	Sortlist                       AddressMatchList // Server side RRSet sorting rules.
	Stacksize                      SizeSpec         // The maximum amount of stack memory the server may use.
	StatsFile                      string           // The pathname of the file the server appends statistics to when instructed to do so.
	StatisticsInterval             int              // Name server statistics will be logged every statistics-interval minutes.
	TcpClients                     int              // The maximum number of simultaneous client TCP connections that the server will accept.
	TcpListenQueue                 int              // The listen queue depth.
	TDHKeyName                     string           // The Diffie-Hellman key name and tag used by the server to generate shared keys with clients using the Diffie-Hellman mode of TKEY.
	TDHKeyTag                      uint64
	TKeyDomain                     string           // The domain appended to the names of all shared keys generated with TKEY.
	Topology                       AddressMatchList // Defines how the outgoing queries are sent to the topologically nearest DNS servers.
	TransferFormat                 TransferFormat   // Zone transfers can be sent using two different formats, one-answer and many-answers.
	TransferSource                 *IPAndPort       // The IPv4 source address to be used for zone transfer with the remote server.
	TransferSourceV6               *IPAndPort       // The IPv6 source address to be used for zone transfer with the remote server.
	TransfersIn                    int              // The maximum number of inbound zone transfers that can be running concurrently.
	TransfersOut                   int              // The maximum number of outbound zone transfers that can be running concurrently.
	TransfersPerNS                 int              // The maximum number of inbound zone transfers that can be concurrently transferring from a given remote name server.
	TreatCrAsSpace                 bool             // (Obsolete) This option was used in BIND 8 to make the server treat carriage return (”\r”) characters the same way as a space or tab character.
	TryTcpRefresh                  bool             // Try to refresh the zone using TCP if UDP queries fail.
	UpdateCheckKsk                 bool             // When set to the default value of yes, check the KSK bit in each key to determine how the key should be used when generating RRSIGs for a secure zone.
	UseAltTransferSource           bool             // Use the alternate transfer sources or not.
	UseIdPool                      bool             // (Obsolete) BIND 9 always allocates query IDs from a pool.
	UseIxfr                        bool             // (Obsolete) If you need to disable IXFR to a particular server or servers, use the provide-ixfr option.
	Version                        string           // The version the server should report via a query of the name version.bind with type TXT, class CHAOS.
	ZeroNoSoaTtl                   bool             // When returning authoritative negative responses to SOA queries set the TTL of the SOA record returned in the authority section to zero.
	ZeroNoSoaTtlCache              bool             // When caching a negative response to a SOA query set the TTL to zero.
	ZoneStats                      bool             // If yes, the server will collect statistical data on all zones (unless specifically turned off on a per-zone basis by specifying zone-statistics no in the zone statement).
}

// NewOptions returns a newly created Options with sane defaults set or an Error if any.
// The Version field is filled from the version parameter.
func NewOptions(version string) (o *Options, err error) {
	return defaultOptions(version)
}

func aclStr(f strutil.Formatter, optname string, opt AddressMatchList) {
	if len(opt) != 0 {
		f.Format("%s {%i\n", optname)
		opt.str(f)
		f.Format("%u};\n")
	}
}

func ipsStr(f strutil.Formatter, optname string, ips IPs) {
	if len(ips) != 0 {
		f.Format("%s {%i\n", optname)
		for _, item := range ips {
			item.str(f)
			f.Format(";\n")
		}
		f.Format("%u};\n")
	}
}

func ipAndPortStr(f strutil.Formatter, optname string, x *IPAndPort) {
	if x == nil {
		return
	}

	f.Format("%s ", optname)
	x.str(f)
	f.Format(";\n")
}

func (x *Options) str(f strutil.Formatter) {
	f.Format("options {%i\n")
	f.Format("acache-cleaning-interval %d;\n", x.ACacheCleaningInterval)
	f.Format("acache-enable %t;\n", x.ACacheEnable)
	f.Format("additional-from-auth %t;\n", x.AdditionalFromAuth)
	f.Format("additional-from-cache %t;\n", x.AdditionalFromCache)

	aclStr(f, "allow-notify", x.AllowNotify)
	aclStr(f, "allow-query", x.AllowQuery)
	aclStr(f, "allow-query-on", x.AllowQueryOn)
	aclStr(f, "allow-query-cache", x.AllowQueryCache)
	aclStr(f, "allow-query-cache-on", x.AllowQueryCacheOn)
	aclStr(f, "allow-recursion", x.AllowRecursion)
	aclStr(f, "allow-recursion-on", x.AllowRecursionOn)
	aclStr(f, "allow-transfer", x.AllowTransfer)
	aclStr(f, "allow-update", x.AllowUpdate)
	aclStr(f, "allow-update-forwarding", x.AllowUpdateForwarding)
	aclStr(f, "allow-v6-synthesis", x.AllowV6Synthesis)
	ipsStr(f, "also-notify", x.AlsoNotify)
	ipAndPortStr(f, "alt-transfer-source", x.AltTransferSource)
	ipAndPortStr(f, "alt-transfer-source-v6", x.AltTransferSourceV6)
	f.Format("auth-nxdomain %t;\n", x.AuthNXDomain)
	if len(x.AvoidV4UdpPorts) != 0 {
		f.Format("avoid-v4-udp-ports {%i\n")
		x.AvoidV4UdpPorts.str(f)
		f.Format("%u\n};\n")
	}
	if len(x.AvoidV6UdpPorts) != 0 {
		f.Format("avoid-v6-udp-ports {%i\n")
		x.AvoidV6UdpPorts.str(f)
		f.Format("%u\n};\n")
	}
	if x.BindKeysFile != "" {
		f.Format("bindkeys-file %q;\n", x.BindKeysFile)
	}
	aclStr(f, "blackhole", x.Blackhole)
	f.Format("check-dup-records %s;\n", x.CheckDupRecs)
	f.Format("check-integrity %t;\n", x.CheckIntegrity)
	f.Format("check-mx %s;\n", x.CheckMx)
	f.Format("check-mx-cname %s;\n", x.CheckMxCname)
	f.Format("check-names master %s;\n", x.CheckNamesMaster)
	f.Format("check-names slave %s;\n", x.CheckNamesSlave)
	f.Format("check-names response %s;\n", x.CheckNamesResponse)
	f.Format("check-sibling %t;\n", x.CheckSibling)
	f.Format("check-srv-cname %s;\n", x.CheckSrvCname)
	f.Format("check-wildcard %t;\n", x.CheckWildcard)
	if x.CleaningInterval != 0 {
		f.Format("cleaning-interval %d;\n", x.CleaningInterval)
	}
	f.Format("clients-per-query %d;\n", x.ClientsPerQuery)
	f.Format("coresize %s;\n", x.Coresize)
	f.Format("datasize %s;\n", x.Datasize)
	if x.DeallocateOnExit {
		f.Format("deallocate-on-exit %t;\n", x.DeallocateOnExit)
	}
	if x.Dialup != DialupNo {
		f.Format("dialup %s;\n", x.Dialup)
	}
	if x.Directory != "" {
		f.Format("directory %q;\n", x.Directory)
	}
	for _, x := range x.DisableAlgorithms {
		f.Format("disable-algorithms ")
		x.str(f)
	}
	for _, x := range x.DisableEmptyZone {
		f.Format("disable-empty-zone %q;\n", x)
	}
	f.Format("dnssec-accept-expired %t;\n", x.DNSSecAcceptExpired)
	f.Format("dnssec-dnskey-kskonly %t;\n", x.DNSSecDnsKeyKskOnly)
	f.Format("dnssec-enable %t;\n", x.DNSSecEnable)
	for _, x := range x.DNSSecLookaside {
		f.Format("dnssec-lookaside %s;\n", x)
	}
	for _, x := range x.DNSSecMustBeSecure {
		f.Format("dnssec-must-be-secure %s;\n", x)
	}
	f.Format("dnssec-secure-to-insecure %t;\n", x.DNSSecSecure2Insecure)
	f.Format("dnssec-validation %t;\n", x.DNSSecValidation)
	x.DualStackServers.str(f)
	if x.DumpFile != "" {
		f.Format("dump-file %q;\n", x.DumpFile)
	}
	f.Format("ixfr-from-differences %s;\n", x.IxfrFromDiffs)
	f.Format("edns-udp-size %d;\n", x.EdnsUdpSize)
	if x.EmptyContact != "" {
		f.Format("empty-contact %q;\n", x.EmptyContact)
	}
	if x.EmptyServer != "" {
		f.Format("empty-server %q;\n", x.EmptyServer)
	}
	f.Format("empty-zones-enable %t;\n", x.EmptyZonesEnable)
	if x.FakeIQuery {
		f.Format("fake-iquery %t;\n", x.FakeIQuery)
	}
	if x.FetchGlue {
		f.Format("fetch-glue %t;\n", x.FetchGlue)
	}
	f.Format("files %s;\n", x.Files)
	f.Format("flush-zones-on-shutdown %t;\n", x.FlushZonesOnShutdown)
	f.Format("forward %s;\n", x.Forward)
	ipsStr(f, "forwarders", x.Forwarders)
	if x.HasOldClients {
		f.Format("has-old-clients %t;\n", x.HasOldClients)
	}
	if x.Hostname != "" {
		f.Format("hostname %q;\n", x.Hostname)
	} else {
		f.Format("hostname none;\n")
	}
	if x.HostStatistics {
		f.Format("host-statistics %t;\n", x.HostStatistics)
	}
	if x.HostStatisticsMax != 0 {
		f.Format("host-statistics-max %d;\n", x.HostStatisticsMax)
	}
	f.Format("heartbeat-interval %d;\n", x.HeartbeatInterval)
	f.Format("interface-interval %d;\n", x.InterfaceInterval)
	if x.KeyDirectory != "" {
		f.Format("key-directory %q;\n", x.KeyDirectory)
	}
	f.Format("lame-ttl %d;\n", x.LameTtl)
	for _, item := range x.ListenOn {
		f.Format("listen-on")
		item.str(f)
	}
	for _, item := range x.ListenOnV6 {
		f.Format("listen-on-v6")
		item.str(f)
	}
	if x.MaintainIxfrBase {
		f.Format("maintain-ixfr-base %t;\n", x.MaintainIxfrBase)
	}
	f.Format("master-file-format %s;\n", x.MasterFileFormat)
	if x.MatchMappedAddresses {
		f.Format("match-mapped-addresses %t;\n", x.MatchMappedAddresses)
	}
	f.Format("max-acache-size %s;\n", x.MaxACacheSize)
	f.Format("max-cache-size %s;\n", x.MaxCacheSize)
	f.Format("max-cache-ttl %d;\n", x.MaxCacheTtl)
	if x.MaxIxfrLogSize != 0 {
		f.Format("max-ixfr-log-size %d;\n", x.MaxIxfrLogSize)
	}
	f.Format("max-journal-size %s;\n", x.MaxJournalSize)
	f.Format("max-clients-per-query %d;\n", x.MaxClientsPerQuery)
	f.Format("max-ncache-ttl %d;\n", x.MaxNCacheTtl)
	if x.MinRefreshTime != 0 {
		f.Format("min-refresh-time %d;\n", x.MinRefreshTime)
	}
	if x.MaxRefreshTime != 0 {
		f.Format("max-refresh-time %d;\n", x.MaxRefreshTime)
	}
	if x.MaxRetryTime != 0 {
		f.Format("max-retry-time %d;\n", x.MaxRetryTime)
	}
	if x.MinRetryTime != 0 {
		f.Format("min-retry-time %d;\n", x.MinRetryTime)
	}
	f.Format("max-udp-size %d;\n", x.MaxUdpSize)
	f.Format("max-transfer-idle-in %d;\n", x.MaxXferIdleIn)
	f.Format("max-transfer-idle-out %d;\n", x.MaxXferIdleOut)
	f.Format("max-transfer-time-in %d;\n", x.MaxXferTimeIn)
	f.Format("max-transfer-time-out %d;\n", x.MaxXferTimeOut)
	f.Format("memstatistics %t;\n", x.MemStats)
	if x.MemStatsFile != "" {
		f.Format("memstatistics-file %q;\n", x.MemStatsFile)
	}
	f.Format("minimal-responses %t;\n", x.MinimalResponses)
	f.Format("min-roots %d;\n", x.MinRoots)
	if x.PIDFile != "" {
		f.Format("pid-file %q;\n", x.PIDFile)
	}
	if x.MultipleCnames {
		f.Format("multiple-cnames %t;\n", x.MultipleCnames)
	}
	f.Format("multi-master %t;\n", x.MultiMaster)
	if x.NamedXfer != "" {
		f.Format("named-xfer %q;\n", x.NamedXfer)
	}
	f.Format("notify %s;\n", x.Notify)
	f.Format("notify-delay %d;\n", x.NotifyDelay)
	ipAndPortStr(f, "notify-source", x.NotifySource)
	ipAndPortStr(f, "notify-source-v6", x.NotifySourceV6)
	f.Format("port %d;\n", x.Port)
	if x.PreferredGlue != nil {
		f.Format("preferred-glue %s;\n", x.PreferredGlue)
	} else {
		f.Format("preferred-glue none;\n")
	}
	if x.ProvideIxfr != nil {
		f.Format("provide-ixfr %t;\n", *x.ProvideIxfr)
	}
	if x.Querylog != nil {
		f.Format("querylog %t;\n", *x.Querylog)
	}
	ipAndPortStr(f, "query-source", x.QuerySource)
	ipAndPortStr(f, "query-source-v6", x.QuerySourceV6)
	if x.RandomDevice != "" {
		f.Format("random-device %q;\n", x.RandomDevice)
	}
	f.Format("recursion %t;\n", x.Recursion)
	if x.RecursingFile != "" {
		f.Format("recursing-file %q;\n", x.RecursingFile)
	}
	f.Format("recursive-clients %d;\n", x.RecursiveClients)
	if x.RequestIxfr != nil {
		f.Format("request-ixfr %t;\n", *x.RequestIxfr)
	}
	f.Format("reserved-sockets %d;\n", x.ReservedSockets)
	f.Format("rfc2308-type1 %t;\n", x.Rfc2308Type1)
	if x.RootDelegationOnly != nil {
		f.Format("root-delegation-only")
		if ex := *x.RootDelegationOnly; len(ex) != 0 {
			f.Format(" exclude {%i\n")
			for _, v := range ex {
				f.Format("%q;\n", v)
			}
			f.Format("%u}")
		}
		f.Format(";\n")
	}
	if len(x.RRSetOrder) != 0 {
		f.Format("rrset-order {%i\n")
		for _, v := range x.RRSetOrder {
			v.str(f)
			f.Format(";\n")
		}
		f.Format("%u};\n")
	}
	f.Format("serial-query-rate %d;\n", x.SerialQueryRate)
	if x.SerialQueries != 0 {
		f.Format("serial-queries %d;\n", x.SerialQueries)
	}
	if x.ServerId != "" {
		f.Format("server-id %q;\n", x.ServerId)
	}
	f.Format("session-keyalg %s;\n", x.SessionKeyAlg)
	if x.SessionKeyFile != "" {
		f.Format("session-keyfile %q;\n", x.SessionKeyFile)
	}
	if x.SessionKeyName != "" {
		f.Format("session-keyname %q;\n", x.SessionKeyName)
	}
	n := x.SigValidityIntervalExpireHours
	if x.SigValidityIntervalBase > 7 {
		n /= 24
	}
	f.Format("sig-validity-interval %d %d;\n", x.SigValidityIntervalBase, n)
	f.Format("sig-signing-nodes %d;\n", x.SigSigningNodes)
	f.Format("sig-signing-signatures %d;\n", x.SigSigningSignatures)
	f.Format("sig-signing-type %d;\n", x.SigSigningType)
	aclStr(f, "sortlist", x.Sortlist)
	f.Format("stacksize %s;\n", x.Stacksize)
	if x.StatsFile != "" {
		f.Format("statistics-file %q;\n", x.StatsFile)
	}
	f.Format("statistics-interval %d;\n", x.StatisticsInterval)
	f.Format("tcp-clients %d;\n", x.TcpClients)
	f.Format("tcp-listen-queue %d;\n", x.TcpListenQueue)
	if x.TDHKeyName != "" {
		f.Format("tkey-dhkey %q %d;\n", x.TDHKeyName, x.TDHKeyTag)
	}
	if x.TKeyDomain != "" {
		f.Format("tkey-domain %q;\n", x.TKeyDomain)
	}
	aclStr(f, "topology", x.Topology)
	f.Format("transfer-format %s;\n", x.TransferFormat)
	ipAndPortStr(f, "transfer-source", x.TransferSource)
	ipAndPortStr(f, "transfer-source-v6", x.TransferSourceV6)
	f.Format("transfers-in %d;\n", x.TransfersIn)
	f.Format("transfers-out %d;\n", x.TransfersOut)
	f.Format("transfers-per-ns %d;\n", x.TransfersPerNS)
	if x.TreatCrAsSpace {
		f.Format("treat-cr-as-space %t;\n", x.TreatCrAsSpace)
	}
	f.Format("try-tcp-refresh %t;\n", x.TryTcpRefresh)
	f.Format("update-check-ksk %t;\n", x.UpdateCheckKsk)
	f.Format("use-alt-transfer-source %t;\n", x.UseAltTransferSource)
	if x.UseIdPool {
		f.Format("use-id-pool %t;\n", x.UseIdPool)
	}
	if x.UseIxfr {
		f.Format("use-ixfr %t;\n", x.UseIxfr)
	}
	if x.Version != "" {
		f.Format("version %q;\n", x.Version)
	} else {
		f.Format("version none;\n")
	}
	f.Format("zero-no-soa-ttl %t;\n", x.ZeroNoSoaTtl)
	f.Format("zero-no-soa-ttl-cache %t;\n", x.ZeroNoSoaTtlCache)
	f.Format("zone-statistics %t;\n", x.ZoneStats)
	f.Format("%u};\n")
}

func (x *Options) String() string {
	return str(x)
}

// ZoneClass* constants are the values of the Zone.Class tag
//TODO => rr.Class
const (
	ZoneClassInternet ZoneClass = iota
	ZoneClassHesiod
	ZoneClassChaosnet
)

// ZoneClass is the type of the Zone.Class tag
type ZoneClass int

func (x *ZoneClass) str(f strutil.Formatter) {
	switch *x {
	default:
		panic(fmt.Errorf("unexpected ZoneClass %d", *x))
	case ZoneClassInternet:
		f.Format("IN")
	case ZoneClassHesiod:
		f.Format("HS")
	case ZoneClassChaosnet:
		f.Format("CHAOS")
	}
}

func (x ZoneClass) String() string {
	return str(&x)
}

// ZoneType is the type of the Zone.Type tag
type ZoneType int

// ZoneType* constants are the values of the Zone.Type tag
const (
	ZoneTypeMaster ZoneType = iota
	ZoneTypeHint
)

func (x *ZoneType) str(f strutil.Formatter) {
	switch *x {
	default:
		panic(fmt.Errorf("unexpected ZoneType %d", *x))
	case ZoneTypeMaster:
		f.Format("master")
	case ZoneTypeHint:
		f.Format("hint")
	}
}

func (x ZoneType) String() string {
	return str(&x)
}

func (x *Zone) str(f strutil.Formatter) {
	f.Format("zone %q %s {%i\n", x.Name, x.Class)
	f.Format("type %s;\n", x.Type)
	if x.File != "" {
		f.Format("file %q;\n", x.File)
	}
	f.Format("%u};\n")
}

func (x *Zone) String() string {
	return str(x)
}

// Zones is a slice of all zone statements data found in a named.conf file.
type Zones []*Zone

func (x *Zones) str(f strutil.Formatter) {
	for _, item := range *x {
		item.str(f)
	}
}

func (x *Zones) String() string {
	return str(x)
}

// AutoDNSSEC is the type of the Zone.AutoDNSSEC field.
type AutoDNSSEC int

const (
	AutoDNSSECOff AutoDNSSEC = iota
	AutoDNSSECAllow
	AutoDNSSECMaintain
	AutoDNSSECCreate
)

// Master is the type of Masters.List item. Either the Include or the other fields
// are valid but not both of these possibilities at once.
type Master struct {
	Include   string    // Name of a named master list to include in this list.
	IPAndPort IPAndPort // Master IP and optional port number.
	Key       string    // Key string.
}

func (m *Master) str(f strutil.Formatter) {
	if m.Include != "" {
		f.Format("%q", m.Include)
		return
	}

	m.IPAndPort.str(f)
	if m.Key != "" {
		f.Format(" key %q", m.Key)
	}
}

func (m *Master) String() string {
	return str(m)
}

// Masters is the type of data of the 'masters' statement.
type Masters struct {
	Name string   // Name of this masters list
	Port *IPPort  // Optional port number.
	List []Master // Items of this masters list.
}

func (m *Masters) str(f strutil.Formatter) {
	f.Format("masters %q", m.Name)
	if m.Port != nil {
		f.Format(" port %d", *m.Port)
	}
	f.Format(" {%i\n")
	for _, v := range m.List {
		v.str(f)
		f.Format(";\n")
	}
	f.Format("%u};\n")
}

func (m *Masters) String() string {
	return str(m)
}

// A zone is a point of delegation in the DNS tree. A zone consists of those contiguous 
// parts of the domain tree for which a name server has complete information and over which it has
// authority. It contains all domain names from a certain point downward in the domain tree except those
// which are delegated to other zones. A delegation point is marked by one or more NS records in the
// parent zone, which should be matched by equivalent NS records at the root of the delegated zone.
type Zone struct {
	Name  string    // Zone name.
	Class ZoneClass // Which class this Zone is.
	Type  ZoneType  // Which type this Zone is.
	File  string    // File name of the zone data file.

	AllowNotify    AddressMatchList // Specifies which hosts are allowed to notify this server, a slave, of zone changes in addition to the zone masters.
	AllowQuery     AddressMatchList // Specifies which hosts are allowed to ask ordinary DNS questions.
	AllowQueryOn   AddressMatchList // Specifies which local addresses can accept ordinary DNS questions.
	AllowTransfer  AddressMatchList // Specifies which hosts are allowed to receive zone transfers from the server.
	AllowUpdate    AddressMatchList // Specifies which hosts are allowed to submit Dynamic DNS updates for master zones.
	AlsoNotify     IPs              // Defines a global list of IP addresses of name servers that are also sent NOTIFY messages whenever a fresh copy of the zone is loaded, in addition to the servers listed in the zone’s NS records.
	AutoDNSSEC     AutoDNSSEC       // Zones configured for dynamic DNS may also use this option to allow varying levels of autonatic DNSSEC key management.
	CheckIntegrity bool             // Perform post load zone integrity checks on master zones.
	CheckMx        WarnFailIgnore   // Check whether the MX record appears to refer to a IP address.
	CheckNames     WarnFailIgnore   // This option is used to restrict the character set and syntax of certain domain names in master/slave/response files.
	CheckWildcard  bool             // This option is used to check for non-terminal wildcards.
	Database       string           // Specifies the type of database to be used for storing the zone data.
	Dialup         DialupOption     // If yes, then the server treats all zones as if they are doing zone transfers across a dial-on-deman dialup link, which can be brought up by traffic originating from this server.

	// This option is only meaningful if the forwarders list is not empty. A value of first, the
	// default, causes the server to query the forwarders first — and if that doesn’t answer the question,
	// the server will then look for the answer itself. If only is specified, the server will only query the
	// forwarders.
	Forward Forward

	// The forwarding facility can be used to create a large site-wide cache on a few servers, reducing traffic
	// over links to external name servers. It can also be used to allow queries by servers that do not have
	// direct access to the Internet, but wish to look up exterior names anyway. Forwarding occurs only on
	// those queries for which the server is not authoritative and does not have the answer in its cache.
	Forwarders IPs

	IxfrBase string // (Obsolete) Was used in BIND 8 to specify the name of the transaction log (journal) file for dynamic update and IXFR.

	// When yes and the server loads a new version of a master zone from its zone
	// file or receives a new version of a slave file by a non-incremental zone transfer, it will compare
	// the new version to the previous one and calculate a set of differences.
	IxfrFromDiffs IxfrFromDiffs

	IxfrTmpFile      string           // (Obsolete) Was an undocumented option in BIND 8.
	Journal          string           // Allow the default journal’s filename to be overridden.
	KeyDirectory     string           // When performing dynamic update of secure zones, the directory where the public and private DNSSEC key files should be found, if different than the current working directory.
	MaintainIxfrBase bool             // (Obsolete) It was used in BIND 8 to determine whether a transaction log was kept for Incremental Zone Transfer.
	MasterFileFormat MasterFileFormat // Specifies the file format of zone files.
	MaxIxfrLogSize   uint64           // (Obsolete) Accepted and ignored for BIND 8 compatibility. The option max-journal-size performs a similar function in BIND 9.
	MaxJournalSize   SizeSpec         // Sets a maximum size for each journal file.

	// These options control the server’s behavior on refreshing a zone (querying for SOA changes)
	// or retrying failed transfers. Usually the SOA values for the zone are used, but these values
	// are set by the master, giving slave server administrators little control over their contents.
	MinRefreshTime uint64
	MinRetryTime   uint64
	MaxRefreshTime uint64
	MaxRetryTime   uint64

	MaxXferIdleOut int        // Outbound zone transfers making no progress in this many minutes will be terminated.
	MaxXferTimeOut int        // Outbound zone transfers running longer than this many minutes will be terminated.
	Notify         Notify     // If yes (the default), DNS NOTIFY messages are sent when a zone the server is authoritative for changes.
	NotifyDelay    int        // The delay, in seconds, between sending sets of notify messages for a zone.
	NotifySource   *IPAndPort // Determines which local source address, and optionally UDP port, will be used to send NOTIFY messages.
	NotifySourceV6 *IPAndPort // Like notify-source, but applies to notify messages sent to IPv6 addresses.
	NotifyToSoa    bool       // If yes do not check the nameservers in the NS RRset against the SOA MNAME. Normally a NOTIFY message is not sent to the SOA MNAME (SOA ORIGIN) as it is supposed to contain the name of the ultimate master.

	//TODO +real type
	Pubkey                         int // (Obsolete) In BIND 8, this option was intended for specifying a public zone key for verification of signatures in DNSSEC signed zones when they are loaded from disk.
	SigSigningNodes                int // Specify the maximum number of nodes to be examined in each quantum when signing a zone with a new DNSKEY.
	SigSigningSignatures           int // Specify a threshold number of signatures that will terminate processing a quantum when signing a zone with a new DNSKEY.
	SigSigningType                 int // Specify a private RDATA type to be used when generating key signing records.
	SigValidityIntervalExpireHours int // Specifies how long before expiry that the signatures will be regenerated.

	//TODO +real type
	UpdatePolicy          int              // Allows more fine-grained control over what updates are allowed.
	ZeroNoSoaTtl          bool             // When returning authoritative negative responses to SOA queries set the TTL of the SOA record returned in the authority section to zero.
	ZoneStats             bool             // If yes, the server will collect statistical data on all zones (unless specifically turned off on a per-zone basis by specifying zone-statistics no in the zone statement).
	AllowUpdateForwarding AddressMatchList // Specifies which hosts are allowed to submit Dynamic DNS updates to slave zones to be forwarded to the master.
	AltTransferSource     *IPAndPort       // An alternate transfer source if the one listed in transfer-source fails and use-alt-transfer-source is set.
	AltTransferSourceV6   *IPAndPort       // An alternate transfer source if the one listed in transfer-source-v6 fails and use-alt-transfer-source is set.
	DNSSecDnsKeyKskOnly   bool             // When this option and update-check-ksk are both set to yes, only key-signing keys (that is, keys with the KSK bit set) will be used to sign the DNSKEY RRset at the zone apex.
	DNSSecSecure2Insecure bool             // Allow a dynamic zone to transition from secure to insecure (i.e., signed to unsigned) by deleting all of the DNSKEY records.
	Masters               Masters          // The masters list specifies one or more IP addresses of master servers that the slave contacts to update its copy of the zone.
	MaxXferIdleIn         int              // Inbound zone transfers making no progress in this many minutes will be terminated.
	MaxXferTimeIn         int              // Inbound zone transfers running longer than this many minutes will be terminated.
	MultiMaster           bool             // This should be set when you have multiple masters for a zone and the addresses refer to different machines.
	TransferSource        *IPAndPort       // The IPv4 source address to be used for zone transfer with the remote server.
	TransferSourceV6      *IPAndPort       // The IPv6 source address to be used for zone transfer with the remote server.
	TryTcpRefresh         bool             // Try to refresh the zone using TCP if UDP queries fail.
	UpdateCheckKsk        bool             // When set to the default value of yes, check the KSK bit in each key to determine how the key should be used when generating RRSIGs for a secure zone.
	UseAltTransferSource  bool             // Use the alternate transfer sources or not.
	DelegationOnly        bool             // This is used to enforce the delegation-only status of infrastructure zones (e.g. COM, NET, ORG).
}

// NewZone return a newly created Zone with the various Zone options
// filled from/linked to values found in 'o'.
func NewZone(o *Options) *Zone {
	z := &Zone{}
	//TODO+
	return z
}

/*

zone zone_name [class] {
	type master;
	//[ allow-query { address_match_list }; ]
	//[ allow-query-on { address_match_list }; ]
	//[ allow-transfer { address_match_list }; ]
	//[ allow-update { address_match_list }; ]
	//[ also-notify { ip_addr [port ip_port] ;
	//[ auto-dnssec allow|maintain|create|off; ]
	//[ check-integrity yes_or_no ; ]
	//[ check-mx (warn|fail|ignore) ; ]
	//[ check-names (warn|fail|ignore) ; ]
	//[ check-wildcard yes_or_no; ]
	//[ database string ; ]
	//[ dialup dialup_option ; ]
	//[ file string ; ]
	//[ forward (only|first) ; ]
	//[ forwarders { [ ip_addr [port ip_port] ; ... ] }; ]
	//[ ixfr-base string ; ]
	//[ ixfr-from-differences yes_or_no; ]
	//[ ixfr-tmp-file string ; ]
	//[ journal string ; ]
	//[ key-directory path_name; ]
	//[ maintain-ixfr-base yes_or_no ; ]
	//[ masterfile-format (text|raw) ; ]
	//[ max-ixfr-log-size number ; ]
	//[ max-journal-size size_spec; ]
	//[ max-refresh-time number ; ]
	//[ max-retry-time number ; ]
	//[ max-transfer-idle-out number ; ]
	//[ max-transfer-time-out number ; ]
	//[ min-refresh-time number ; ]
	//[ min-retry-time number ; ]
	//[ notify yes_or_no | explicit | master-only ; ]
	//[ notify-delay seconds ; ]
	//[ notify-source (ip4_addr | *) [port ip_port] ; ]
	//[ notify-source-v6 (ip6_addr | *) [port ip_port] ; ]
	//[ notify-to-soa yes_or_no; ]
	//[ pubkey number number number string ; ]
	//[ sig-signing-nodes number ; ]
	//[ sig-signing-signatures number ; ]
	//[ sig-signing-type number ; ]
	//[ sig-validity-interval number [number] ; ]
	//[ update-policy local | { update_policy_rule [...] }; ]
	//[ zero-no-soa-ttl yes_or_no ; ]
	//[ zone-statistics yes_or_no ; ]
};

zone zone_name [class] {
	type slave;
	//[ allow-notify { address_match_list }; ]
	//[ allow-query { address_match_list }; ]
	//[ allow-query-on { address_match_list }; ]
	//[ allow-transfer { address_match_list }; ]
	//[ allow-update-forwarding { address_match_list }; ]
	//[ also-notify { ip_addr [port ip_port] ;
	//[ alt-transfer-source (ip4_addr | *) [port ip_port] ; ]
	//[ alt-transfer-source-v6 (ip6_addr | *)
	//[ check-names (warn|fail|ignore) ; ]
	//[ database string ; ]
	//[ dialup dialup_option ; ]
	//[ dnssec-dnskey-kskonly yes_or_no; ]
	//[ dnssec-secure-to-insecure yes_or_no ; ]
	//[ file string ; ]
	//[ forward (only|first) ; ]
	//[ forwarders { [ ip_addr [port ip_port] ; ... ] }; ]
	//[ ixfr-base string ; ]
	//[ ixfr-from-differences yes_or_no; ]
	//[ ixfr-tmp-file string ; ]
	//[ journal string ; ]
	//[ maintain-ixfr-base yes_or_no ; ]
	//[ masterfile-format (text|raw) ; ]
	//[ masters [port ip_port] { ( masters_list | ip_addr
	//[ max-ixfr-log-size number ; ]
	//[ max-journal-size size_spec; ]
	//[ max-refresh-time number ; ]
	//[ max-retry-time number ; ]
	//[ max-transfer-idle-in number ; ]
	//[ max-transfer-idle-out number ; ]
	//[ max-transfer-time-in number ; ]
	//[ max-transfer-time-out number ; ]
	//[ min-refresh-time number ; ]
	//[ min-retry-time number ; ]
	//[ multi-master yes_or_no ; ]
	//[ notify yes_or_no | explicit | master-only ; ]
	//[ notify-delay seconds ; ]
	//[ notify-source (ip4_addr | *) [port ip_port] ; ]
	//[ notify-source-v6 (ip6_addr | *) [port ip_port] ; ]
	//[ notify-to-soa yes_or_no; ]
	//[ pubkey number number number string ; ]
	//[ transfer-source (ip4_addr | *) [port ip_port] ; ]
	//[ transfer-source-v6 (ip6_addr | *) [port ip_port] ; ]
	//[ try-tcp-refresh yes_or_no; ]
	//[ update-check-ksk yes_or_no; ]
	//[ use-alt-transfer-source yes_or_no; ]
	//[ zero-no-soa-ttl yes_or_no ; ]
	//[ zone-statistics yes_or_no ; ]
};

zone zone_name [class] {
	type hint;
	//file string ;
	//[ check-names (warn|fail|ignore) ; ] // Not Implemented.
	//[ delegation-only yes_or_no ; ]
};

zone zone_name [class] {
	type stub;
	//[ allow-query { address_match_list }; ]
	//[ allow-query-on { address_match_list }; ]
	//[ alt-transfer-source (ip4_addr | *) [port ip_port] ; ]
	//[ alt-transfer-source-v6 (ip6_addr | *)
	//[ check-names (warn|fail|ignore) ; ]
	//[ database string ; ]
	//[ delegation-only yes_or_no ; ]
	//[ dialup dialup_option ; ]
	//[ file string ; ]
	//[ forward (only|first) ; ]
	//[ forwarders { [ ip_addr [port ip_port] ; ... ] }; ]
	//[ masterfile-format (text|raw) ; ]
	//[ masters [port ip_port] { ( masters_list | ip_addr
	//[ max-refresh-time number ; ]
	//[ max-retry-time number ; ]
	//[ max-transfer-idle-in number ; ]
	//[ max-transfer-time-in number ; ]
	//[ min-refresh-time number ; ]
	//[ min-retry-time number ; ]
	//[ multi-master yes_or_no ; ]
	//[ pubkey number number number string ; ]
	//[ transfer-source (ip4_addr | *) [port ip_port] ; ]
	//[ transfer-source-v6 (ip6_addr | *)
	//[ use-alt-transfer-source yes_or_no; ]
	//[ zone-statistics yes_or_no ; ]
};

zone zone_name [class] {
	type forward;
	//[ delegation-only yes_or_no ; ]
	//[ forward (only|first) ; ]
	//[ forwarders { [ ip_addr [port ip_port] ; ... ] }; ]
};

zone zone_name [class] {
	type delegation-only;
};

*/
