// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

// Package resolv supports resolv.conf formatted data (see also `man resolv.conf`).
// Supported are conversions from a file or string to an internal representation and back to a string.
package resolv

import (
	"bytes"
	"github.com/cznic/dns"
	"github.com/cznic/fileutil"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
)

// System resolv.conf name
var Sys string

const (
	// data from <resolv.h> and resolv.conf(5)
	resolvNDotsCap         = 15
	resolvTimeoutCap       = 30
	resolvAttepmptsCap     = 5
	resolvMaxNS            = 3
	resolvMaxSearch        = 6
	resolvMaxSearchChars   = 256
	resolvMaxSortlistPairs = 10
	resolvNDotsDefault     = 1
	resolvTimeoutDefault   = 5
	resolvAttepmptsDefault = 2
)

// Cfg represents a resolv.conf with a change/modification guard/handler.
type Cfg struct {
	cfg     *Conf
	changed bool
	mfile   *fileutil.GoMFile
	logger  *dns.Logger
}

// NewCfg returns a newly created Cfg with resolv.Conf initialized from file fname of an Error of any.
// It binds the contained resolv.Conf to fname and on any changes to the fname file the Cfg resolv.Conf
// is reloaded on access via Cfg.Conf().
func NewCfg(fname string, logger *dns.Logger) (c *Cfg, err os.Error) {
	x := &Cfg{cfg: &Conf{}, logger: logger}
	if x.mfile, err = fileutil.NewGoMFile(fname, os.O_RDONLY, 0444, 0); err != nil {
		return
	}

	if err = x.cfg.Load(fname); err != nil {
		return
	}

	x.mfile.SetHandler(func(file *os.File) (err os.Error) {
		if _, err = file.Seek(0, 0); err != nil {
			return
		}

		buf := []byte{}
		if buf, err = ioutil.ReadAll(file); err != nil {
			return
		}

		if err = x.cfg.LoadString(fname, string(buf)); err != nil {
			return
		}

		if logger.Level >= dns.LOG_EVENTS {
			logger.Log("loaded %q", fname)
			if logger.Level >= dns.LOG_DEBUG {
				logger.Log("\n%s", x.cfg)
			}
		}
		x.changed = true
		return
	})

	return x, nil
}

// SetChanged forces next Conf() to handle modification of the wrapped resolv.Conf.
func (c *Cfg) SetChanged() {
	c.mfile.SetChanged()
}

// Conf returns a resolv.Conf from Cfg and an indicator of it's source file has been changed/modificated
// compared to the last invocation of this function or an Error if any.
func (c *Cfg) Conf() (f *Conf, changed bool, err os.Error) {
	if _, err = c.mfile.File(); err != nil {
		return
	}

	f, changed, err, c.changed = c.cfg, c.changed, nil, false
	return
}

// A Conf holds the data found in a resolver configuration file,
// e.g. '/etc/resolv.conf'. See also resolv.conf(5)
type Conf struct {
	// Internet address (in dot notation) of a name server that the resolver should query. 
	Nameserver []net.IP
	// Local domain name.
	Domain string
	// Resolver queries having fewer than ndots dots (default  is  1)
	// in them will be attempted using each component of the search path 
	// in turn until a match is found.
	Search []string
	// This option allows addresses returned by a resolver to be sorted.
	Sortlist []SortlistItem
	Opt      struct {
		Debug bool
		// The number of dots which must appear in a name before an initial absolute query will be made.
		// Default: 1
		Ndots uint
		// Amount of time the resolver will wait for a response from a remote name server before retry.
		// Default: 5
		TimeoutSecs uint
		// Number of times the resolver will send a query to its name servers before giving up.
		// Default: 2
		Attempts uint
		// Round robin selection of nameservers from among those listed.
		Rotate bool
		// Disables the modern BIND checking of incoming hostnames and mail names for invalid characters.
		NoCheckNames bool
		// Try an AAAA query before an A query.
		Inet6 bool
		// This causes reverse IPv6 lookups to be made using the bit-label format described in RFC 2673.
		Ip6ByteString bool
		// Reverse IPv6 lookups are made in the (deprecated) ip6.int zone.
		Ip6Dotint bool
		// Enables support for the DNS extensions described in RFC 2671.
		Edns0 bool
	}
}

// Return a constructed Conf with sane defaults
func NewConf() (c *Conf) {
	c = &Conf{}
	c.Nameserver = make([]net.IP, 0, resolvMaxNS)
	c.Search = make([]string, 0, resolvMaxSearch)
	c.Sortlist = make([]SortlistItem, 0, resolvMaxSortlistPairs)
	c.Opt.Ndots = resolvNDotsDefault
	c.Opt.TimeoutSecs = resolvTimeoutDefault
	c.Opt.Attempts = resolvAttepmptsDefault
	return
}

func (c *Conf) appendNameserver(ip net.IP) {
	n := len(c.Nameserver)
	if n == resolvMaxNS {
		panic(os.NewError("Maximum number of nameservers reached"))
	}
	c.Nameserver = c.Nameserver[:n+1]
	c.Nameserver[n] = ip
}

func (c *Conf) AppendNameserver(ip net.IP) (err os.Error) {
	defer func() {
		if e := recover(); e != nil {
			err = e.(os.Error)
		}
	}()

	c.appendNameserver(ip)
	return
}

func (c *Conf) appendSearch(s string) {
	n := len(c.Search)
	if n == resolvMaxSearch {
		panic(os.NewError("maximum length of the searchliost reached"))
	}
	c.Search = c.Search[:n+1]
	c.Search[n] = s
}

func (c *Conf) AppendSearch(s string) (err os.Error) {
	defer func() {
		if e := recover(); e != nil {
			err = e.(os.Error)
		}
	}()

	c.appendSearch(s)
	return
}

func (c *Conf) appendSortlist(addr, mask net.IP) {
	n := len(c.Sortlist)
	if n == resolvMaxSortlistPairs {
		panic(os.NewError("Maximum length of the sortlist reached"))
	}
	c.Sortlist = c.Sortlist[:n+1]
	c.Sortlist[n] = SortlistItem{addr, mask}
}

func (c *Conf) AppendSortlist(addr, mask net.IP) (err os.Error) {
	defer func() {
		if e := recover(); e != nil {
			err = e.(os.Error)
		}
	}()

	c.appendSortlist(addr, mask)
	return
}

// Load Conf c from a resolv.conf format file fname. Return an Error, if any.
func (c *Conf) Load(fname string) (err os.Error) {
	defer func() {
		if e := recover(); e != nil {
			err = e.(os.Error)
		}
	}()

	buf, err := ioutil.ReadFile(fname)
	if err != nil {
		panic(err)
	}

	return c.LoadString(fname, string(buf))
}

func min(a *uint, b uint) {
	if *a > b {
		*a = b
	}
}

// Load Conf c with from a resolv.conf format string s. Return an Error, if any.
func (c *Conf) LoadString(fname, s string) (err os.Error) {
	lx := newLex(fname, strings.NewReader(s))

	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%s:%d:%d - %s", fname, lx.line, lx.column, e.(os.Error))
		}
	}()

	if yyParse(lx) != 0 {
		panic(os.NewError("syntax error"))
	}

	min(&lx.resolv.Opt.Ndots, resolvNDotsCap)
	min(&lx.resolv.Opt.TimeoutSecs, resolvTimeoutCap)
	min(&lx.resolv.Opt.Attempts, resolvAttepmptsCap)
	*c = *lx.resolv
	return
}

func (c *Conf) String() string {
	buf := bytes.NewBuffer(nil)
	for _, nameserver := range c.Nameserver {
		buf.WriteString(fmt.Sprintf("nameserver %s\n", nameserver))
	}
	if c.Domain != "" {
		buf.WriteString(fmt.Sprintf("domain %s\n", c.Domain))
	}
	if len(c.Search) != 0 {
		buf.WriteString("search")
		for _, item := range c.Search {
			buf.WriteString(fmt.Sprintf(" %s", item))
		}
		buf.WriteString("\n")
	}
	if len(c.Sortlist) != 0 {
		buf.WriteString("sortlist")
		for _, item := range c.Sortlist {
			buf.WriteString(fmt.Sprintf(" %s", &item))
		}
		buf.WriteString("\n")
	}

	opt := bytes.NewBuffer(nil)
	type t struct {
		key  string
		flag bool
	}
	for _, v := range []t{
		{"debug", c.Opt.Debug},
		{"rotate", c.Opt.Rotate},
		{"no-check-names", c.Opt.NoCheckNames},
		{"inet6", c.Opt.Inet6},
		{"ip6-bytestring", c.Opt.Ip6ByteString},
		{"ip6-dotint", c.Opt.Ip6Dotint},
		{"edns0", c.Opt.Edns0}} {
		if v.flag {
			opt.WriteString(fmt.Sprintf(" %s", v.key))
		}
	}
	type n struct {
		key      string
		n        uint
		default_ uint
	}
	for _, v := range []n{
		{"ndots", c.Opt.Ndots, resolvNDotsDefault},
		{"timeout", c.Opt.TimeoutSecs, resolvTimeoutDefault},
		{"attempts", c.Opt.Attempts, resolvAttepmptsDefault}} {
		if v.n != v.default_ {
			opt.WriteString(fmt.Sprintf(" %s:%d", v.key, v.n))
		}
	}
	if opt.Len() != 0 {
		buf.WriteString("options")
		opt.WriteTo(buf)
	}

	return buf.String()
}

type goCfgMsg struct {
	f       *Conf
	changed bool
	error   os.Error
}

// GoCfg is a Cfg wrapped in a goroutine allowing for concurrent access.
type GoCfg struct {
	cfg *Cfg
	rq  chan bool
	re  chan *goCfgMsg
}

// NewGoCfg returns a newly created GoCfg or an Error if any.
// It is assumed there will be only one/few GoCfg instance(s) in an application.
// The instance(s) and it's associated goroutine(s) will never be released.
// This is by design in an atempt to avoid some possibly nasty races on finalization.
// The "impossible to release" doesn't apply when NewGoCfg returns an Error.
func NewGoCfg(fname string, logger *dns.Logger) (c *GoCfg, err os.Error) {
	x := &GoCfg{}
	if x.cfg, err = NewCfg(fname, logger); err != nil {
		return
	}

	x.rq = make(chan bool, 10)
	x.re = make(chan *goCfgMsg, 10)
	c = x
	go func() {
		for {
			<-c.rq // wait for rq
			msg := &goCfgMsg{}
			msg.f, msg.changed, msg.error = c.cfg.Conf()
			c.re <- msg // return response
		}
	}()
	return
}

// Conf returns a Conf from GoCfg and an indicator if it's source file has been changed/modificated
// compared to the last invocation of this function or an Error if any.
// Invocations of Conf are concurrent safe.
func (c *GoCfg) Conf() (f *Conf, changed bool, err os.Error) {
	c.rq <- true
	msg := <-c.re
	return msg.f, msg.changed, msg.error
}

// 'sortlist' Conf option
type SortlistItem struct {
	Addr, NetMask net.IP // The netmask is optional and defaults to the natural netmask of the net.
}

func (i *SortlistItem) String() string {
	if i.NetMask != nil {
		return fmt.Sprintf("%s/%s", i.Addr, i.NetMask)
	}

	return fmt.Sprintf("%s", i.Addr)
}

func init() {
	Sys = "/etc/resolv.conf" //TODO:LSB only
}
