// Copyright (c) 2011 CZ.NIC z.s.p.o. RxAll rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

// Package xfr supports DNS zone transfers.
package xfr

import (
	"github.com/cznic/dns/msg"
	"github.com/cznic/dns/rr"
	"net"
	"os"
)

// MsgHandler is the type of a xfer message handler.
type MsgHandler func(serial int, m *msg.Message) bool

// ErrHandler is the type of a xfer error handler.
type ErrHandler func(serial int, err os.Error) bool

// Error is the type returned for some xfer errors.
type Error struct {
	Reason string
	Msg    *msg.Message
}

func (e *Error) String() string {
	return e.Reason
}

// RxAll attemtps to perform an AXFR zone 'zone' transfer through conn.
//
// On every msg received the msgHandler is invoked. If this handler retruns false
// then the transfer is aborted and a nil Error is returned.
//
// If the errHandler is nil then any error in the xfer causes the transfer to be aborted
// and the error is returned.
//
// If the errHandler is non nil then any error in the xfer is handled over to the errHandler.
// If the errHandler returns false, the transfer is aborted and the same err is returned.
// If the error is from sending the initial query then the serial parameter is < 0.
//
// This function *never* closes the conn.
func RxAll(conn *net.TCPConn, zone string, msgHandler MsgHandler, errHandler ErrHandler) (err os.Error) {
	m := msg.New()
	m.Append(zone, msg.QTYPE_AXFR, rr.CLASS_IN)
	if err = m.Send(conn); err != nil && (errHandler == nil || !errHandler(-1, err)) {
		return
	}

	rxbuf := make([]byte, 1<<16)
	id := m.Header.ID

	for serial := 0; ; serial++ {
		rxbuf = rxbuf[:cap(rxbuf)]
		if _, err = m.ReceiveBuf(conn, rxbuf); err != nil && (errHandler == nil || !errHandler(serial, err)) {
			return
		}

		h := &m.Header
		if h.ID != id ||
			!h.QR ||
			h.Opcode != m.Header.Opcode ||
			h.TC ||
			h.Z != 0 ||
			h.QDCOUNT != 1 {
			if errHandler == nil || !errHandler(serial, &Error{"malformed msg received", m}) {
				return
			}
		}
		if !msgHandler(serial, m) {
			return nil
		}
	}

	panic("unreachable")
}
