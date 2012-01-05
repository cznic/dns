// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

package dns

import (
	"fmt"
	"log"
	"os"
	"path"
)

// The Logger type supports simple/simplified logging based on a log.Logger and dns.LogLevel.
type Logger struct {
	Logger *log.Logger
	Level  LogLevel
}

// NewLogger returns a newly created Logger initialized with logger and level.
// If the logger is nil and level != LOG_NONE then a defualt log.New logger is provided.
func NewLogger(logger *log.Logger, level LogLevel) *Logger {
	if logger == nil && level != LOG_NONE {
		prefix, flags := "", 0
		switch level {
		case LOG_ERRORS:
			flags = log.Ldate | log.Ltime
		case LOG_EVENTS:
			prefix = os.Args[0]
			flags = log.Ldate | log.Ltime
		case LOG_TRACE:
			prefix = os.Args[0]
			flags = log.Ldate | log.Ltime | log.Lshortfile
		case LOG_DEBUG:
			prefix = os.Args[0]
			flags = log.Ldate | log.Ltime | log.Lmicroseconds | log.Llongfile
		}

		if prefix != "" {
			prefix = fmt.Sprintf("[%d %s] ", os.Getpid(), path.Base(prefix))
		}
		logger = log.New(os.Stderr, prefix, flags)
	}
	return &Logger{logger, level}
}

// If l.Logger != nil then Output invokes l.Logger.Output.
// If s contains newlines it is splitted to multiple Outputs.
func (l *Logger) Output(calldepth int, s string) (err error) {
	if l.Logger != nil {
		err = l.Logger.Output(calldepth, s)
	}
	return
}

const depth = 3

func (l *Logger) Log(format string, v ...interface{}) {
	l.Output(depth, fmt.Sprintf(format, v...))
}
