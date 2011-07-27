// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

// Package resolver is a simple DNS resolver.
package resolver

import (
	"github.com/cznic/dns"
	"github.com/cznic/dns/cache"
	"github.com/cznic/dns/hosts"
	"github.com/cznic/dns/msg"
	"github.com/cznic/dns/resolv"
	"github.com/cznic/dns/rr"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type queryConf struct {
	hosts map[string][]net.IP
	ips   map[string][]string
	*resolv.Conf
	*Resolver
}

func (q *queryConf) hostsChanged(f *hosts.File) (err os.Error) {
	q.hosts = map[string][]net.IP{}
	q.ips = map[string][]string{}

	add := func(name string, ip net.IP) {
		q.hosts[name] = append(q.hosts[name], ip)
	}

	for _, item := range *f {
		name := strings.ToLower(item.CanonicalName)
		ip := item.IP
		sip := string([]byte(ip))
		if _, ok := q.ips[sip]; ok {
			return fmt.Errorf("duplicate ip entry %q", ip.String())
		}

		q.ips[sip] = append(append([]string{}, name), item.Aliases...)
		add(strings.ToLower(item.CanonicalName), ip)
		for _, name := range item.Aliases {
			add(strings.ToLower(name), ip)
		}
	}
	return
}

func (q *queryConf) qhosts(name string) (y []net.IP, ok bool) {
	y, ok = q.hosts[name]
	return
}

func (q *queryConf) qips(ip net.IP) (y []string, ok bool) {
	y, ok = q.ips[string([]byte(ip))]
	return
}

// Build a query task list from a hostname.
func (q *queryConf) hostqlist(name string) (list []string) {
	labels, err := dns.Labels(name)
	if err != nil {
		if q.Resolver.log.Level >= dns.LOG_ERRORS {
			q.Resolver.log.Log("FAIL %s: %s", name, err)
		}
		return
	}

	dots := len(labels) - 1
	ndots := int(q.Conf.Opt.Ndots)
	domain := q.Conf.Domain
	if domain == "" {
		domain = dns.Host2domain(q.Resolver.hostName)
	}
	rooted := dns.IsRooted(name)
	if rooted || dots >= ndots {
		list = append(list, name) // initial absolute query
	}
	if !rooted && dots < ndots {
		rname := dns.RootedName(name)
		if domain != "" {
			list = append(list, rname+domain)
		}
		list = append(list, name)
		for _, s := range q.Conf.Search {
			list = append(list, rname+s)
		}
	}
	return
}

type goStrMapBool struct {
	m    map[string]bool
	lock sync.Mutex
}

func newGoStrMapBool() *goStrMapBool {
	return &goStrMapBool{m: map[string]bool{}}
}

// LookupResult is the type of the Resolver.Lookup() result.
type LookupResult int

// Values of LookupResult.
const (
	LookupOK           LookupResult = iota // Sucess
	LookupAliased                          // Sucess, but QNAME is an alias and the result is for it's canonical name
	LookupNameError                        // QNAME doesn't exist
	LookupDataNotFound                     // QNAME does exist, but no data for the combination of QTYPE and QCLASS were found
	LookupFail                             // E.g. can't contact any DNS server (wrong conf or network communication error)
	LookupAliasLoop                        // Detected a cycle in the aliases chain
	LookupAliasError                       // QNAME is an alias to a non existing canonical name
)

var LookupResultStr = map[LookupResult]string{
	LookupOK:           "Sucess",
	LookupAliased:      "Sucess. QNAME is an alias and the result is for it's canonical name",
	LookupNameError:    "QNAME doesn't exist",
	LookupDataNotFound: "QNAME does exist, but no data for the combination of QTYPE and QCLASS were found",
	LookupFail:         "Lookup fail. Could be also wrong resolver configuration or network communication error.",
	LookupAliasLoop:    "Detected a cycle in the aliases chain",
	LookupAliasError:   "QNAME is an alias to a non existing canonical name",
}

// Resolver is a DNS resolver.
type Resolver struct {
	cache                 *cache.Cache
	hostName              string
	log                   *dns.Logger
	getQueryConf          func() *queryConf
	pendingA, pendingAAAA *goStrMapBool // paralel NS addr requests recursion protector
}

func New(hostsFName, resolvFName string, logger *dns.Logger) (r *Resolver, err os.Error) {
	r = &Resolver{cache: cache.New(), log: logger, pendingA: newGoStrMapBool(), pendingAAAA: newGoStrMapBool()}

	defer func() {
		if e := recover(); e != nil {
			if r.log.Level >= dns.LOG_ERRORS {
				r.log.Log("FAIL New: %s", e.(os.Error))
			}
			r = nil
		}
	}()

	if r.log.Level >= dns.LOG_TRACE {
		r.log.Log("New(hosts %q resolv %q)", hostsFName, resolvFName)
	}

	if hostsFName == "" {
		hostsFName = hosts.Sys
	}

	r.hostName, err = os.Hostname()
	if err != nil {
		panic(err)
	}

	var hostsCfg *hosts.Cfg
	hostsCfg, err = hosts.NewCfg(hostsFName, logger)
	if err != nil {
		panic(err)
	}

	if resolvFName == "" {
		resolvFName = resolv.Sys
	}
	var resolvCfg *resolv.Cfg
	resolvCfg, err = resolv.NewCfg(resolvFName, logger)
	if err != nil {
		panic(err)
	}

	hostsCfg.SetChanged()
	resolvCfg.SetChanged()

	r.getQueryConf = func() *queryConf { //TODO -> can be a method now
		v := &queryConf{Resolver: r}
		hfile, _, herr := hostsCfg.File()
		if herr != nil {
			if r.log.Level >= dns.LOG_ERRORS {
				r.log.Log("FAIL hostsCfg.File: %s", herr)
			}
		}
		if err := v.hostsChanged(hfile); err != nil {
			if r.log.Level >= dns.LOG_ERRORS {
				r.log.Log("FAIL hostsChanged: %s", err)
			}
		}
		cfile, _, cerr := resolvCfg.Conf()
		if cerr != nil {
			if r.log.Level >= dns.LOG_ERRORS {
				r.log.Log("FAIL resolvCfg.File: %s", cerr)
			}
		}
		v.Conf = cfile
		return v
	}

	if r.log.Level >= dns.LOG_TRACE {
		r.log.Log("New() OK")
	}
	return
}

// Cache returns the Resolver's Cache
func (r *Resolver) Cache() *cache.Cache {
	return r.cache
}

// Logger returns the Resolver's Logger
func (r *Resolver) Logger() *dns.Logger {
	return r.log
}

func (r *Resolver) getHostByName(name string, qtype msg.QType) (ipList []net.IP, redirects rr.RRs, err os.Error) {
	qc := r.getQueryConf()
	// query trylist
	qlist := qc.hostqlist(strings.ToLower(strings.TrimSpace(name)))

	for _, q := range qlist {
		if ipList, _ = qc.qhosts(q); ipList != nil { // resolved from "hosts"
			return
		}
	}

	for i, q := range qlist {
		rrs, cnames, result, e := r.Lookup(q, qtype, rr.CLASS_IN, false)
		if e != nil {
			err = e
			return
		}

		redirects = cnames
		switch result {
		case LookupNameError:
			if i+1 < len(qlist) {
				continue
			}

			fallthrough
		default:
			err = fmt.Errorf(LookupResultStr[result])
			return
		case LookupOK, LookupAliased:
			for _, rec := range rrs {
				switch x := rec.RData.(type) {
				default:
					log.Fatalf("FAIL %T", x)
				case *rr.A:
					ipList = append(ipList, x.Address)
				case *rr.AAAA:
					ipList = append(ipList, x.Address)
				}
			}
			return
		}
		panic("unreachable")

	}
	panic("unreachable")
}

// GetHostByNameIPv4 will try to Lookup an IN A address (i.e. IPv4) list for name.
// Used CNAMEs chain, if any, is returned in redirects.
func (r *Resolver) GetHostByNameIPv4(name string) (ipList []net.IP, redirects rr.RRs, err os.Error) {
	return r.getHostByName(name, msg.QTYPE_A)
}

// GetHostByNameIPv6 will try to Lookup an IN AAAA address (i.e. IPv6) list for name.
// Used CNAMEs chain, if any, is returned in redirects.
func (r *Resolver) GetHostByNameIPv6(name string) (ipList []net.IP, redirects rr.RRs, err os.Error) {
	return r.getHostByName(name, msg.QTYPE_AAAA)
}

// GetHostByName will try to Lookup an IN A or AAAA address (i.e. IPv4 or IPv6) list for name.
// Used CNAMEs chain, if any, is returned in redirects. Initially an attempt for IPv4 addresses
// is performed. Query for the IPv6 addresses is afterwards invoked iff no IPv4 addresses were
// returned by the initial attempt. If preferIPv6 == true then the above query order is reversed.
func (r *Resolver) GetHostByName(name string, preferIPv6 bool) (ipList []net.IP, redirects rr.RRs, err os.Error) {
	a, b := (*Resolver).GetHostByNameIPv4, (*Resolver).GetHostByNameIPv6
	if preferIPv6 {
		a, b = b, a
	}

	if ipList, redirects, err = a(r, name); len(ipList) != 0 {
		return
	}

	return b(r, name)
}

// GetHostByAddr will try to resolve an IPv4 or IPv6 address to host name(s).
func (r *Resolver) GetHostByAddr(ip net.IP) (hosts []string, err os.Error) {
	qc := r.getQueryConf()
	if hosts, _ = qc.qips(ip); hosts != nil {
		return // resolved from hosts
	}

	name := dns.RevLookupName(ip)
	if name == "" {
		return nil, fmt.Errorf("GetHostByAddr:invalid ip '% x'", ip)
	}

	var rrs rr.RRs
	var rslt LookupResult
	if rrs, _, rslt, err = r.Lookup(name, msg.QTYPE_PTR, rr.CLASS_IN, false); err != nil {
		return
	}

	switch rslt {
	default:
		err = fmt.Errorf("GetHostByAddr: %s", LookupResultStr[rslt])
	case LookupOK, LookupAliased:
		for _, v := range rrs {
			hosts = append(hosts, v.RData.(*rr.PTR).PTRDName)
		}
	}
	return
}

func (r *Resolver) sbelt() (s *srvlist) {
	s = &srvlist{conf: r.getQueryConf()}
	servers := s.conf.Conf.Nameserver
	if len(servers) == 0 {
		s.servers = []server{{zone: "DefaultLocalNameServer.", name: "DefaultLocalNameServer.", attempts: int(s.conf.Conf.Opt.Attempts), ips: []net.IP{dns.DefaultLocalNameServer()}, matchcount: -1}}
		return
	}

	s.servers = make([]server, len(servers))
	for i, srv := range servers {
		n := fmt.Sprintf("%d.SBELT.", i)
		s.servers[i] = server{zone: n, name: n, attempts: int(s.conf.Conf.Opt.Attempts), ips: []net.IP{srv}, matchcount: -1}
	}
	return
}

func (r *Resolver) cached(name string, want func(*rr.RR) bool) (wanted rr.RRs) {
	if rrs, hit := r.cache.Get(name); hit {
		wanted, _ = rrs.Filter(want)
	}
	return
}

func (r *Resolver) needNSAdr(name string) {
	const retry = 60e9 // Don't retry for a minute

	f := func(p *goStrMapBool, q msg.QType) {
		p.lock.Lock()         // X++
		defer p.lock.Unlock() // X--
		if p.m[name] {        // P
			return
		}

		// !P && X
		p.m[name] = true // P++
		p.lock.Unlock()  // X--

		r.Lookup(name, q, rr.CLASS_IN, true) //TODO Param? Support anything outside CLASS_IN?
		<-time.After(retry)
		p.lock.Lock()            // X++
		p.m[name] = false, false // P--
	}

	go f(r.pendingA, msg.QTYPE_A)
	go f(r.pendingAAAA, msg.QTYPE_AAAA)
}

// Lookup is a general DNS lookup function (rfc1034/p.30). It attempts to retrieve arbitrary
// information from the DNS. The caller supplies a sname, stype and sclass, and wants all of the
// matching RRs. Lookup should normally report "DNS lookup error" results via the return result variable.
// A non-nil Error is returned for any non-lookup error event. The rd parameter is the msg.Messsage.Header
// "Recursion Desired" flag. Lookup CNAMEs chain walked, if any, is returned in redirects.
func (r *Resolver) Lookup(sname string, stype msg.QType, sclass rr.Class, rd bool) (answer, redirects rr.RRs, result LookupResult, err os.Error) {

	defer func() {
		if e := recover(); e != nil {
			if r.log.Level >= dns.LOG_ERRORS {
				r.log.Log("FAIL Lookup error: %s", e.(os.Error))
			}
		}
	}()

	var slist *srvlist
	var reply *msg.Message
	var srv server // current server asked
	var ip net.IP  // current IP asked

	retry := 0   // number of requests sent for missing addresses of known nameservers
	iserver := 0 // index into slist servers
	sname = dns.RootedName(strings.ToLower(sname))
	aliases := map[string]bool{strings.ToLower(sname): true} // CNAME loop detection

	// rfc1034/5.3.3
	// The top level algorithm has four steps:

step1:
	//=================================================================
	//   1. See if the answer is in local information, and if so return
	//      it to the client.

	bestmatch := -2 // sbelt has -1
	nodata, nxdomain, sname0 := false, false, sname

	answer = r.cached(sname,

		func(rec *rr.RR) bool {
			switch {
			case sclass != rec.Class:
				return false
			case stype == msg.QTYPE_STAR:
				return true
			case rec.Type == rr.TYPE_NXDOMAIN:
				nxdomain = true
				return false
			case rec.Type == rr.TYPE_NODATA && rr.Type(stype) == rec.RData.(*rr.NODATA).Type:
				nodata = true
				return false
			case rec.Type == rr.TYPE_CNAME && stype != msg.QTYPE_CNAME:
				cname := strings.ToLower(rec.RData.(*rr.CNAME).Name)
				if aliases[cname] {
					result = LookupAliasLoop
					return false
				}

				redirects = append(redirects, rec)
				sname = cname
				aliases[sname] = true
				result = LookupAliased
				return false
			default:
				return rr.Type(stype) == rec.Type
			}
			panic("unreachable")
		})

	switch {
	case result == LookupAliasLoop:
		return
	case len(answer) != 0:
		return
	case sname != sname0:
		goto step1
	case nxdomain: // NXDOMAIN resolved from cache
		switch result {
		case LookupAliased:
			result = LookupAliasError
		default:
			result = LookupNameError
		}
		return
	case nodata: // NODATA resolved from cache
		result = LookupDataNotFound
		return
	}

step2:
	//=================================================================
	//   2. Find the best servers to ask.
	// Step 2 looks for a name server to ask for the required data.  The
	// general strategy is to look for locally-available name server RRs,
	// starting at SNAME, then the parent domain name of SNAME, the
	// grandparent, and so on toward the root.  Thus if SNAME were
	// Mockapetris.ISI.EDU, this step would look for NS RRs for
	// Mockapetris.ISI.EDU, then ISI.EDU, then EDU, and then . (the root).
	// These NS RRs list the names of hosts for a zone at or above SNAME.  Copy
	// the names into SLIST.  Set up their addresses using local data.  It may
	// be the case that the addresses are not available.  The resolver has many
	// choices here; the best is to start parallel resolver processes looking
	// for the addresses while continuing onward with the addresses which are
	// available.

	var slabels []string
	if slabels, err = dns.Labels(sname); err != nil {
		return
	}

	slist = &srvlist{conf: r.getQueryConf()}
	srvmap := map[string]bool{}

	for len(slabels) != 0 {
		q := strings.Join(slabels, ".")

		if nss := r.cached(q,

			func(rec *rr.RR) bool {
				if rec.Class == sclass && rec.Type == rr.TYPE_NS {
					nm := strings.ToLower(rec.RData.(*rr.NS).NSDName)
					// Name servers for a domain are themselves generally anywhere in the DNS tree 
					// and the same NS may serve otherwise unrelated parts of the DNS tree
					// (i.e. separated zones). Thus we can see the same one(s) again while walking the slabels towards root.
					// Avoid adding a same NS more than once to the SLIST.
					if !srvmap[nm] {
						srvmap[nm] = true
						return true
					} // else rejecting duplicate nameserver nm
				}
				return false

			}); nss != nil {

			for _, ns := range nss {
				// check ns NS
				var matchcount int
				if matchcount, err = dns.MatchCount(sname, ns.Name); err != nil {
					if r.log.Level >= dns.LOG_ERRORS {
						r.log.Log("Matchcount: %s", err)
					}
					err = nil // not fatal, but ignore the NS RR
					continue
				}

				if matchcount <= bestmatch { // ignore
					continue
				}

				// matchcount > bestmatch => chance
				nsdname := ns.RData.(*rr.NS).NSDName

				if as := r.cached(nsdname,

					func(r *rr.RR) bool {
						return r.Class == sclass && (r.Type == rr.TYPE_A || r.Type == rr.TYPE_AAAA)

					}); as != nil {

					// got len(as) addresses for ns
					srv := server{name: nsdname, zone: ns.Name, matchcount: matchcount, attempts: int(slist.conf.Conf.Opt.Attempts)}
					for _, a := range as {
						var ip net.IP
						switch x := a.RData.(type) {
						default:
							log.Fatalf("FAIL internal error %T", x)
						case *rr.A:
							ip = x.Address
						case *rr.AAAA:
							ip = x.Address
						}
						srv.ips = append(srv.ips, ip)
					}
					slist.servers = append(slist.servers, srv)
					continue
				}

				// We have a nice candidate NS but have no A nor AAAA RRs for it.
				// Could be due to missing glue record(s) or their expired TTLs.
				// Enter emergency panic mode for the missing address(es).
				r.needNSAdr(nsdname)
				retry++

			}
		}
		slabels = slabels[1:] // level up
	}

	if len(slist.servers) == 0 {
		slist = r.sbelt()
		if r.log.Level >= dns.LOG_DEBUG {
			r.log.Log("%q: using sbelt", sname)
		}
	}
	sort.Sort(slist)
	iserver = 0

step3:
	//=================================================================
	//   3. Send them queries until one returns a response.

	if r.log.Level >= dns.LOG_DEBUG {
		r.log.Log("slist servers %d", len(slist.servers))
	}
	rxbuf := make([]byte, 2000)

asking:
	for {
		if len(slist.servers) == 0 {
			if r.log.Level >= dns.LOG_DEBUG {
				r.log.Log("Lookup %q fail, no servers to ask", sname)
			}
			result = LookupFail
			return
		}

		if iserver >= len(slist.servers) {
			if r.log.Level >= dns.LOG_DEBUG {
				r.log.Log("Lookup %q giving up without getting a valid response", sname)
			}
			result = LookupFail
			return
		}

		srv = slist.servers[iserver]
		if srv.matchcount <= bestmatch {
			if retry == 0 {
				if r.log.Level >= dns.LOG_DEBUG {
					r.log.Log("Lookup %q giving up due to no progress in matching", sname)
				}
				result = LookupFail
				return
			}

			// retry due to pending NS addresses requests
			<-time.After(1e9 / 2)
			retry >>= 1
			goto step2

		}

		const qmark = "------------------------------------------------------------------------------"
		const rmark = "=============================================================================="

		// try server srv
		for attempts := 0; attempts < srv.attempts; attempts++ {
			for _, ip = range srv.ips {
				m := msg.New()
				m.Question.Append(sname, stype, sclass)
				m.Header.RD = rd // Recursion Desired
				if r.log.Level >= dns.LOG_TRACE {
					if r.log.Level >= dns.LOG_DEBUG {
						r.log.Log("\n%s(QUERY MSG for %q @ %s)\n%s\n%s\n", qmark, srv.name, ip, m, qmark)
					} else {
						r.log.Log("asking %q @ %s, Q: %s", srv.name, ip, m.Question)
					}
				}
				c, err := net.DialUDP("udp", nil, &net.UDPAddr{ip, 53})
				if err != nil {
					if r.log.Level >= dns.LOG_ERRORS {
						r.log.Log("FAIL net.DialUDP: %s", err)
					}
					continue
				}

				defer c.Close()

				c.SetTimeout(int64(slist.conf.Conf.Opt.TimeoutSecs) * 1e9)
				if _, reply, err = m.ExchangeBuf(c, rxbuf); err != nil {
					if r.log.Level >= dns.LOG_ERRORS {
						r.log.Log("FAIL ExchangeBuf: %s", err)
					}
					continue
				}

				// got a response
				if r.log.Level >= dns.LOG_TRACE {
					if r.log.Level >= dns.LOG_DEBUG {
						r.log.Log("\n%s(REPLY MSG from %q @ %s)\n%s\n%s\n", rmark, srv.name, ip, reply, rmark)
					} else {
						r.log.Log("got a response for %q from %q @ %s", sname, srv.name, ip)
					}
				}
				h := &reply.Header
				reject := h.ID != m.Header.ID ||
					!h.QR ||
					h.Opcode != m.Header.Opcode ||
					h.TC ||
					h.Z != 0 ||
					h.QDCOUNT != m.Header.QDCOUNT

				if reject {
					continue

				}

				break asking // response accepted

			}
		}

		iserver++
	}

	if srv.matchcount <= bestmatch {
		log.Fatalf("FAIL internal error %d <= %d", srv.matchcount, bestmatch)
	}

	if r.log.Level > dns.LOG_DEBUG {
		r.log.Log("%q bestmatch %d -> %d", sname, bestmatch, srv.matchcount)
	}
	bestmatch = srv.matchcount

	//step4:

	other := rr.RRs{}
	cnames := rr.RRs{} // only those matching sname
	soa := (*rr.RR)(nil)
	soadata := (*rr.SOA)(nil)

	answer, other = reply.Answer.Filter(func(r *rr.RR) bool {
		return sclass == r.Class && (stype == msg.QTYPE_STAR || r.Type == rr.Type(stype)) && strings.ToLower(r.Name) == sname
	})
	cnames, other = other.Filter(func(r *rr.RR) bool {
		return sclass == r.Class && r.Type == rr.TYPE_CNAME && strings.ToLower(r.Name) == sname
	})
	soas, ns := reply.Authority.Filter(func(r *rr.RR) bool {
		return sclass == r.Class && r.Type == rr.TYPE_SOA
	})
	// Authority NSs sanity check
	ns, _ = ns.Filter(func(rec *rr.RR) (y bool) {
		mc, _ := dns.MatchCount(sname, rec.Name)
		return mc > bestmatch
	})
	if len(soas) == 1 {
		soa = soas[0]
		soadata = soa.RData.(*rr.SOA)
	}

	//=================================================================
	//   4. Analyze the response, either:

	switch {

	//-----------------------------------------------------------------
	//       4.a. if the response answers the question or contains a name
	//            error, cache the data as well as returning it back to
	//            the client.
	case reply.RCODE == msg.RC_NO_ERROR && len(answer) != 0:
		r.cache.Add(reply.Answer, soas, ns, reply.Additional)
		answer.Unique() // improve some bad configured server responses
		return

	case reply.RCODE == msg.RC_NAME_ERROR:
		r.cache.Add(reply.Answer, soas, ns, reply.Additional)

		//   rfc2038/5 cache NXDOMAIN
		if reply.AA && len(soas) == 1 {
			ttl := soa.TTL
			if ttl2 := int32(soadata.Minimum); ttl2 < ttl {
				ttl = ttl2
			}
			r.cache.Add(rr.RRs{&rr.RR{sname, rr.TYPE_NXDOMAIN, sclass, ttl, &rr.NXDOMAIN{}}})
		}

		switch result {
		case LookupAliased:
			result = LookupAliasError
		default:
			result = LookupNameError
		}

		return

	//-----------------------------------------------------------------
	//   rfc2038/2.2 - No Data
	//
	//   NODATA is indicated by an answer with the RCODE set to NOERROR and no
	//   relevant answers in the answer section.  The authority section will
	//   contain an SOA record, or there will be no NS records there.	
	case reply.RCODE == msg.RC_NO_ERROR && reply.ANCOUNT == 0 && (len(soas) == 1 || len(ns) == 0):
		r.cache.Add(reply.Answer, soas, ns, reply.Additional)

		//   rfc2038/5 cache NODATA
		if reply.AA {
			ttl := soa.TTL
			if ttl2 := int32(soadata.Minimum); ttl2 < ttl {
				ttl = ttl2
			}
			r.cache.Add(rr.RRs{&rr.RR{sname, rr.TYPE_NODATA, sclass, ttl, &rr.NODATA{rr.Type(stype)}}})
		}
		result = LookupDataNotFound
		return

	//-----------------------------------------------------------------
	//       4.c. if the response shows a CNAME and that is not the
	//            answer itself, cache the CNAME, change the SNAME to the
	//            canonical name in the CNAME RR and go to step 1.
	case reply.RCODE == msg.RC_NO_ERROR && len(cnames) == 1:
		r.cache.Add(reply.Answer, soas, ns, reply.Additional)

		cn := cnames[0]
		cname := cn.RData.(*rr.CNAME)
		for chain := true; chain; {

			sname = strings.ToLower(cname.Name) // next name in chain

			if aliases[sname] {
				result = LookupAliasLoop
				return
			}

			aliases[sname] = true
			redirects = append(redirects, cn)
			chain = false
			for _, cn = range other {
				if cn.Type == rr.TYPE_CNAME && strings.ToLower(cn.Name) == sname {
					cname, chain = cn.RData.(*rr.CNAME), true
					break
				}
			}
		}
		result = LookupAliased
		goto step1

	//-----------------------------------------------------------------
	//       4.b. if the response contains a better delegation to other
	//            servers, cache the delegation information, and go to
	//            step 2.
	case reply.RCODE == msg.RC_NO_ERROR && len(ns) != 0:
		r.cache.Add(soas, ns, reply.Additional)
		goto step2

	//-----------------------------------------------------------------
	//       4.d. if the response shows a servers failure or other
	//            bizarre contents, delete the server from the SLIST and
	//            go back to step 3.
	default:
		goto step3 // "delete from the SLIST" is performed by iserver incrementing in step 3
	}

	panic("unreachable")
}

type server struct {
	attempts   int
	zone       string
	matchcount int
	name       string
	ips        []net.IP
}

type srvlist struct {
	conf    *queryConf
	servers []server
}

// Implementation of sort.Interface
func (s *srvlist) Len() int {
	return len(s.servers)
}

// Implementation of sort.Interface
func (s *srvlist) Less(i, j int) bool {
	return s.servers[i].matchcount > s.servers[j].matchcount // sort descending matchcounts
}

// Implementation of sort.Interface
func (s *srvlist) Swap(i, j int) {
	s.servers[i], s.servers[j] = s.servers[j], s.servers[i]
}
