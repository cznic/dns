// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package proxy provides simple DNS proxies.
//
// - WIP SNAPSHOT - UNFINISHED - NOT COMPLETE - DO NOT USE - API MAY CHANGE -
package proxy

import (
	"fmt"
	"github.com/cznic/dns"
	"github.com/cznic/dns/msg"
	"net"
	"strings"
)

type Handler interface {
	Handle(m *msg.Message, c net.Conn) (response *msg.Message, err error)
}

type HandlerFunc func(m *msg.Message, c net.Conn) (response *msg.Message, err error)

func (h HandlerFunc) Handle(m *msg.Message, c net.Conn) (response *msg.Message, err error) {
	return h(m, c)
}

// New creates a new DNS proxy listening at network, addr or returns a non nil
// error.  The proxy routes incomming traffic according to 'routes'.
//
// If 'stop' is not nil then a non nil 'stopped' channel is returned and any
// value sent to the 'stop' channel will stop the proxy and an undefined value
// is sent back to the 'stopped' channel just before the proxy server exists.
// If 'stop' is nil then a nil 'stopped' channel is returned instead.
//
// Note: Passing a non-nil 'stop' channel and failing to send a stop message to
// it leads to goroutines leaking and/or resource blocking/exhausting. It's
// okay for a standalone proxy process to not use the 'stop' channel.
// Everything will be then cleaned up by the OS on process termination/exit.
//
// If 'errs' is not nil then any failures are reported to it. If sending to the
// 'errs' channel would block the proxy from operating then the error is
// dropped.  To avoid that, use a buffered channel and a consumer goroutine on
// the other end of the channel.
//
// Valid network values are only: "tcp", "tcp4",
// "tcp6", "udp", "udp4", "udp6".
// Valid addr examples:
//	"ns.example.com"
//	"2.3.4.5" // IPv4
//	"[::]:53" // Ipv6
//
// The port part, e.g. ':53' is optional and port 53 is the deault.
//
// A route key consist of two white space separated fields, for example:
//	". 8.8.8.8"
//	"company.local. 10.20.30.40:53"
//	"foo.bar.com. ns.example.com"
// i.e. a zone followed by a routing address. Again, the port part is optional
// and defaults to 53. If any of the routing targets cannot be resolved the
// proxy is not created and an error is reported.  Any route value may be nil,
// then a DefaultHandler is used. Example:
//	routes := map[string]Handler{
//		". 8.8.8.8":                     nil,
//		"example.com. 10.20.30.40:5353": HandlerFunc(myHandler),
//	}
// I.e. every DNS query for anything in zone 'example.com.' will be routed to
// '10.20.30.40:5353' and handled by 'myhandler'. Queries for any other zone
// will be routed to '8.8.8.8:53' and handled by DefaultHandler.
//
// A complete example of a bare bones tcp/udp proxy app:
//	package main
//
//	import (
//		"github.com/cznic/dns/proxy"
//		"log"
//	)
//
//	func main() {
//		routes := map[string]Handler{
//			". 8.8.8.8":                         nil,
//			"www.example.com. 10.20.30.40:5353": nil,
//		}
//		errs := make(chan error, 100)
//		if _, err := proxy.New("udp", ":53", routes, nil, errs); err != nil {
//			log.Fatal(err)
//		}
//
//		if _, err := proxy.New("tcp", ":53", routes, nil, errs); err != nil {
//			log.Fatal(err)
//		}
//
//		for err := range errs {
//			log.Print(err)
//		}
//	}
func New(network, addr string, routes map[string]Handler, stop <-chan int, errs chan<- error) (stopped chan<- int, err error) {
	var listenAt net.Addr
	network = strings.ToLower(network)
	if listenAt, err = resolve(network, addr); err != nil {
		return
	}

	rt := dns.NewTree()
	for k, v := range routes {
		flds := strings.Fields(k)
		if len(flds) != 2 {
			err = fmt.Errorf("expected 2 fields in %q", k)
			return
		}

		var a net.Addr
		if a, err = resolve(network, flds[1]); err != nil {
			return
		}

		if v == nil {
			v = DefaultHandler
		}
		rt.Add(flds[0], target{a, v}, func(interface{}) interface{} {
			err = fmt.Errorf("duplicate routing for zone %q", flds[0])
			return nil
		})
		if err != nil {
			return
		}
	}
	if stop != nil {
		stopped = make(chan int)
	}
	rep := func(err error) { // error reporter
		if errs == nil {
			return
		}

		select {
		case errs <- err:
		}
	}
	switch x := listenAt.(type) {
	case *net.UDPAddr:
		var conn *net.UDPConn
		if conn, err = net.ListenUDP(network, x); err != nil {
			return
		}

		go func() { // server
			defer func() { // stop reporter
				if stop != nil {
					select {
					case stopped <- 1:
					}
				}
			}()

			if stop != nil { // stopper
				go func() {
					<-stop
					conn.Close()
				}()
			}

			// serve
			for {
				buf := make([]byte, DefaultBuf)
				m := &msg.Message{}
				// c -> p -> s -> p -> c
				_, cAddr, err := m.ReceiveUDP(conn, buf) // c -> p
				if err != nil {
					rep(err)
					if opErr, ok := err.(*net.OpError); ok {
						if !opErr.Temporary() {
							return
						}
					}

					continue
				}
				// handle request
				go func(m *msg.Message, cAddr *net.UDPAddr) {
					if len(m.Question) != 1 {
						rep(fmt.Errorf("malformed query %q", m))
						return
					}

					qname := m.Question[0].QNAME
					t := rt.Match(qname)
					if t == nil {
						rep(fmt.Errorf("no route for %q", qname))
						return
					}

					target := t.(target)
					sConn, err := net.DialUDP(network, nil, target.addr.(*net.UDPAddr))
					if err != nil {
						rep(err)
						return
					}

					m, err = target.handler.Handle(m, sConn) // p -> s -> p
					cerr := sConn.Close()
					if cerr != nil {
						rep(cerr)
					}
					if err != nil {
						rep(err)
						return
					}

					w := dns.NewWirebuf()
					m.Encode(w)
					_, err = conn.WriteToUDP(w.Buf, cAddr) // p -> c
					if err != nil {
						rep(err)
					}
				}(m, cAddr)

			}
		}()
	case *net.TCPAddr:
		err = fmt.Errorf("TODO")
	default:
		err = fmt.Errorf("internal error %T", x)
	}
	return
}

type target struct {
	addr    net.Addr
	handler Handler
}

func resolve(network, addr string) (a net.Addr, err error) {
	typ, ok := validNets[network]
	if !ok {
		return nil, fmt.Errorf("invalid net %q", network)
	}

	addr = strings.ToLower(addr)
	switch typ {
	case udp:
		var x *net.UDPAddr
		if x, err = net.ResolveUDPAddr(network, addr); err != nil {
			return
		}

		if x.Port == 0 {
			x.Port = 53
		}
		return x, nil
	case tcp:
		var x *net.TCPAddr
		if x, err = net.ResolveTCPAddr(network, addr); err != nil {
			return
		}

		if x.Port == 0 {
			x.Port = 53
		}
		return x, nil
	}
	return nil, fmt.Errorf("internal error, typ %d", typ)
}

const (
	udp = iota
	tcp
)

var validNets = map[string]int{
	"tcp":  tcp,
	"tcp4": tcp,
	"tcp6": tcp,
	"udp":  udp,
	"udp4": udp,
	"udp6": udp,
}

// DefaultBuf is the buffer size used for packets routed by DefaultHandler.  It
// can be set in initialization of some app. Reasonable values are in [512,
// 4096], but it depends on specific traffic. For simple A only queries 512 may
// be sometimes enough.
var DefaultBuf = 1024

// DefaultHandler is the routing default handler, supplied for `"zone addr":
// nil` routes.  If no message translating/modification is required then this
// is all what's needed.
var DefaultHandler Handler = HandlerFunc(func(m *msg.Message, c net.Conn) (response *msg.Message, err error) {
	return m.Exchange(c, DefaultBuf)
})
