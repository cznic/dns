// Copyright (c) 2011 CZ.NIC z.s.p.o. RxAll rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

// Package xfr supports DNS zone transfers.
package xfr

import (
	"github.com/cznic/dns/msg"
	"github.com/cznic/dns/rr"
	"fmt"
	"net"
)

// RxMsgHandler is the type of a xfer received message handler.
type RxMsgHandler func(serial int, m *msg.Message) bool

// ErrHandler is the type of a xfer error handler.
type ErrHandler func(serial int, err error) bool

// Error is the type returned for some xfer errors.
type Error struct {
	Reason string
	Msg    *msg.Message
}

func (e *Error) Error() string {
	return e.Reason
}

// RxAll attemtps to perform an AXFR zone 'zone' transfer through conn.
//
// On every msg received the msgHandler is invoked. If this handler returns false
// then the transfer is aborted and a nil Error is returned. The msgHandler should
// return false on seeing a message with the 'closing' SOA RR, otherwise the behavior of RxAll us undefined.
//
// If the errHandler is nil then any error in the xfer causes the transfer to be aborted
// and the error is returned.
//
// If the errHandler is non nil then any error in the xfer is handled over to the errHandler.
// If the errHandler returns false, the transfer is aborted and the same err is returned.
// If the error is from sending the initial query then the serial parameter is < 0.
//
// This function *never* closes the conn.
func RxAll(conn *net.TCPConn, zone string, msgHandler RxMsgHandler, errHandler ErrHandler) (err error) {
	serial := 0
	defer func() {
		if e := recover(); e != nil {
			err = e.(error)
			if errHandler == nil || !errHandler(serial, err) {
				return
			}

			err = nil // handled by errHandler
		}
	}()

	m := msg.New()
	m.Append(zone, msg.QTYPE_AXFR, rr.CLASS_IN)
	if err = m.Send(conn); err != nil && (errHandler == nil || !errHandler(-1, err)) {
		return
	}

	rxbuf := make([]byte, 1<<16)
	id := m.Header.ID

	for serial := 0; ; serial++ {
		rxbuf = rxbuf[:cap(rxbuf)]
		if _, err = m.ReceiveTCP(conn, rxbuf); err != nil && (errHandler == nil || !errHandler(serial, err)) {
			return
		}

		if h := &m.Header; h.ID != id ||
			!h.QR ||
			h.Opcode != m.Header.Opcode ||
			h.TC ||
			h.Z ||
			h.QDCOUNT != 1 {
			if errHandler == nil || !errHandler(serial, &Error{"invalid msg received", m}) {
				return
			}
		}

		if !msgHandler(serial, m) {
			return nil
		}
	}

	panic("unreachable")
}

// RxRRHandler is the DNS RR handler type of HandleRxMsg. If the handler returns false
// then the xfer is aborted.
type RxRRHandler func(serial int, r *rr.RR) bool

// HandleMsg returns a pre-built MsgHandler for RxAll which invokes the provided RRHandler
// for every DNS RR found in the answer section of 'm'. Usage example:
//	err := xfr.RxAll(myConn, myZone, HandleMsg(myRRHandler), myErrHandler)
// The record handler 'h' sees the first SOA record, and all subsequent RRs including the final,
// "closing" SOA RR. 
func HandleRxMsg(h RxRRHandler) RxMsgHandler {
	n := 0
	return func(serial int, m *msg.Message) bool {
		var r *rr.RR
		for _, r = range m.Answer {
			if n == 0 && r.Type != rr.TYPE_SOA {
				panic(fmt.Errorf("invalid first RR Type %s\n", r.Type))
			}

			if !h(n, r) {
				return false
			}

			n++
		}
		return n == 0 || r.Type != rr.TYPE_SOA
	}
}
