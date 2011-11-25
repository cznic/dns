// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

// Package pcat supports reading files produce by the pcat utility which is a
// part of the NLnetLabs' ldns project.
//
// See also: http://nlnetlabs.nl/projects/ldns/
package pcat

import (
	"fmt"
	"io"
)

type lex struct {
	buf     []byte
	column  int
	current byte
	line    int
	src     io.ByteReader
}

func newLex(src io.ByteReader) *lex {
	l := &lex{src: src, line: 1, column: 1}
	l.getc()
	return l
}

func (l *lex) getc() (b byte, err error) {
	switch b = l.current; b {
	case 0:
		break
	case '\n':
		l.line++
		l.column = 0
		fallthrough
	default:
		l.column++
		l.buf = append(l.buf, b)
	}
	l.current = 0
	b, err = l.src.ReadByte()
	if err != nil {
		b = 0
		if err != io.EOF {
			return
		}
		err = nil
	}
	l.current = b
	return
}

// Record captures data form one record in the pcat produced text file.
type Record struct {
	Id    int    // Sequential number
	Query []byte // What was sent to server in wire format
	Reply []byte // What was received from server in wire format
}

// Implementation of fmt.Stringer
func (r *Record) String() string {
	return fmt.Sprintf("%d\n%x\n%x", r.Id, r.Query, r.Reply)
}

// Scan scans a pcat formatted text file from src, assuming file name is
// 'name'. Handler 'handler' is called for every Record found in src. If
// handler returns false the scanning process is aborted and Scan returns err
// == nil.  If there is any error detected while scanning then the scanning is
// aborted as well and the error is returned.
func Scan(name string, src io.ByteReader, handler func(*Record) bool) (err error) {
	l := newLex(src)

	defer func() {
		switch e := recover(); {
		case e == nil, e == io.EOF:
			// nop
		default:
			err = fmt.Errorf("%s:%d:%d %s", name, l.line, l.column, e)
		}
	}()

	for {
		var r *Record
		switch r, err = l.scan(); {
		case err != nil:
			panic(err)
		case r == nil || !handler(r):
			return
		}
	}
	panic("unreachable")
}
