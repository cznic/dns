// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package proxy provides simple DNS proxies.
package proxy

import (
	"fmt"
	"github.com/cznic/dns"
	"github.com/cznic/dns/msg"
	"github.com/cznic/dns/rr"
	"net"
	"sync"
	"testing"
)

func udpClient(pAddr *net.UDPAddr, n int) error {
	for i := 0; i < n; i++ {
		m := msg.New()
		m.Question.A("www.example.com.", rr.CLASS_IN)
		conn, err := net.DialUDP("udp", nil, pAddr)
		if err != nil {
			return err
		}
		m, err = m.Exchange(conn, DefaultBuf)
		if err != nil {
			return err
		}

		if x := len(m.Answer); x != 1 {
			return fmt.Errorf("len(m.Answer) == %d", x)
		}

		r := m.Answer[0]
		if x := r.Type; x != rr.TYPE_A {
			return fmt.Errorf("answer.Type == %s", x)
		}

		rrA := r.RData.(*rr.A)
		if x := rrA.Address.String(); x != "1.2.3.4" {
			return fmt.Errorf("answer IP == %s", x)
		}
	}
	return nil
}

var ip1234 = net.ParseIP("1.2.3.4")

func udpServer(sAddr *net.UDPAddr, errs chan error) (sConn *net.UDPConn, err error) {
	sConn, err = net.ListenUDP("udp", sAddr)
	if err != nil {
		return
	}

	go func() {
		for {
			buf := make([]byte, DefaultBuf)
			m := &msg.Message{}
			_, pAddr, err := m.ReceiveUDP(sConn, buf)
			if err != nil {
				errs <- err
				return
			}

			go func(m *msg.Message, pAddr *net.UDPAddr) {

				if x := len(m.Question); x != 1 {
					panic(fmt.Errorf("len(m.Question == %d", x))
				}

				q := m.Question[0]
				if x := q.QNAME; x != "www.example.com." {
					panic(fmt.Errorf("QNAME == %s", x))
				}

				m.QR = true
				m.RCODE = msg.RC_NO_ERROR
				m.Answer = rr.RRs{&rr.RR{"www.example.com", rr.TYPE_A, rr.CLASS_IN, 1, &rr.A{ip1234}}}
				w := dns.NewWirebuf()
				m.Encode(w)
				_, err = sConn.WriteToUDP(w.Buf, pAddr)
				if err != nil {
					errs <- err
				}
			}(m, pAddr)

		}
	}()
	return
}

func testCS(t *testing.T, port, n int) {
	errs := make(chan error, 1e3)
	sAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatal(err)
	}

	sConn, err := udpServer(sAddr, errs)
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
	loop:
		for {
			select {
			case err := <-errs:
				t.Error(err)
			default:
				break loop
			}
		}
		if err := recover(); err != nil {
			t.Error(err)
		}
		if err := sConn.Close(); err != nil {
			t.Error(err)
		}
	}()

	if err = udpClient(sAddr, n); err != nil {
		panic(err)
	}
}

var mtx sync.Mutex
var port = 5555

func getPort() (p int) {
	mtx.Lock()
	port++
	p = port
	defer mtx.Unlock()
	return
}

func TestCS(t *testing.T) {
	testCS(t, getPort(), 1)
	testCS(t, getPort(), 10)
	testCS(t, getPort(), 5e3)
}

func benchCS(b *testing.B, port, n int) {
	b.StopTimer()
	errs := make(chan error, 1e3)
	sAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		b.Fatal(err)
	}

	sConn, err := udpServer(sAddr, errs)
	if err != nil {
		b.Fatal(err)
	}

	defer func() {
	loop:
		for {
			select {
			case err := <-errs:
				b.Error(err)
			default:
				break loop
			}
		}
		if err := recover(); err != nil {
			b.Error(err)
		}
		if err := sConn.Close(); err != nil {
			b.Error(err)
		}
	}()

	b.StartTimer()
	err = udpClient(sAddr, n)
	b.StopTimer()
	if err != nil {
		panic(err)
	}
}

func BenchmarkCS(b *testing.B) {
	benchCS(b, getPort(), b.N)
}
