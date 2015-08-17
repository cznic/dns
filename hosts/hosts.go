// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

// Package hosts supports hosts formatted data (see also `man hosts`).
// Supported are conversions from a file or string to an internal
// representation and back to a string.
package hosts

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/cznic/dns"
	"github.com/cznic/fileutil"
)

// System hosts name
var Sys = "/etc/hosts" //TODO:LSB only

// Cfg represents a hosts.File with a change/modification guard/handler.
// Methods of Cfg are synchronized; multiple goroutines may invoke them
// concurrently.
type Cfg struct {
	cfg     *File
	changed bool
	mfile   *fileutil.GoMFile
	logger  *dns.Logger
	mu      sync.Mutex
}

// NewCfg returns a newly created Cfg with hosts.File initialized from file fname or an Error of any.
// It binds the contained hosts.File to fname and on any changes to the fname file the Cfg hosts.File
// is reloaded on access via Cfg.File().
func NewCfg(fname string, logger *dns.Logger) (c *Cfg, err error) {
	x := &Cfg{cfg: &File{}, logger: logger}
	if x.mfile, err = fileutil.NewGoMFile(fname, os.O_RDONLY, 0444, 0); err != nil {
		return
	}

	if err = x.cfg.Load(fname); err != nil {
		return
	}

	x.mfile.SetHandler(func(file *os.File) (err error) {
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

// SetChanged forces next File() to handle modification of the wrapped hosts.File.
func (c *Cfg) SetChanged() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.mfile.SetChanged()
}

// File returns a hosts.File from Cfg and an indicator of its source file has been changed/modificated
// compared to the last invocation of this function or an Error if any.
func (c *Cfg) File() (f *File, changed bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, err = c.mfile.File(); err != nil {
		return
	}

	f, changed, err, c.changed = c.cfg, c.changed, nil, false
	return
}

// A File holds items found in a hosts file,
// e.g. '/etc/hosts'. See also hosts(5)
type File []*FileItem

// Load File from a hosts format file fname. Return an Error, if any.
func (h *File) Load(fname string) (err error) {
	defer func() {
		if e := recover(); e != nil {
			*h = nil
			err = e.(error)
		}
	}()

	var buf []byte
	buf, err = ioutil.ReadFile(fname)
	if err != nil {
		panic(err)
	}
	return h.LoadString(fname, string(buf))
}

// Load File from a hosts format string s. Return an Error, if any.
func (h *File) LoadString(fname, s string) (err error) {
	lx := newLex(strings.NewReader(s))

	defer func() {
		if e := recover(); e != nil {
			*h = nil
			err = fmt.Errorf("%s:%d:%d - %s", fname, lx.line, lx.column, e.(error))
		}
	}()

	if yyParse(lx) != 0 {
		panic(errors.New("syntax error"))
	}

	*h = lx.hosts
	return
}

func (h *File) String() string {
	buf := bytes.NewBuffer(nil)
	for _, item := range *h {
		buf.WriteString(item.String())
		buf.WriteString("\n")
	}
	return buf.String()
}

// An FileItem holds an item found in a hosts file,
// e.g. '/etc/hosts'. See also hosts(5)
type FileItem struct {
	IP            net.IP   // Well, it's an IP address
	CanonicalName string   // Per specs canocalized hostname
	Aliases       []string // Possibly empty hostname's aliases list
}

func (i *FileItem) String() string {
	buf := bytes.NewBuffer(nil)
	buf.WriteString(fmt.Sprintf("%s %s", i.IP, i.CanonicalName))
	for _, alias := range i.Aliases {
		buf.WriteString(" ")
		buf.WriteString(alias)
	}
	return buf.String()
}

type goCfgMsg struct {
	f       *File
	changed bool
	error   error
}

// GoCfg is a Cfg wrapped in a goroutine allowing for concurrent access.
type GoCfg struct {
	cfg *Cfg
	rq  chan bool
	re  chan *goCfgMsg
}

// NewGoCfg returns a newly created GoCfg or an Error if any.
// It is assumed there will be only one/few GoCfg instance(s) in an application.
// The instance(s) and its associated goroutine(s) will never be released.
// This is by design in an atempt to avoid some possibly nasty races on finalization.
// The "impossible to release" doesn't apply when NewGoCfg returns an Error.
func NewGoCfg(fname string, logger *dns.Logger) (c *GoCfg, err error) {
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
			msg.f, msg.changed, msg.error = c.cfg.File()
			c.re <- msg // return response
		}
	}()
	return
}

// File returns a File from GoCfg and an indicator if its source file has been changed/modificated
// compared to the last invocation of this function or an Error if any.
// Invocations of File are concurrent safe.
func (c *GoCfg) File() (f *File, changed bool, err error) {
	c.rq <- true
	msg := <-c.re
	return msg.f, msg.changed, msg.error
}
