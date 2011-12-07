# Copyright 2009 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

include $(GOROOT)/src/Make.inc

TARG=github.com/cznic/dns/pcat

GOFILES=\
	db.go\
	pcat.go\
	scanner.go\

CLEANFILES += lex.yy.go temp_db *~

include $(GOROOT)/src/Make.pkg

scanner.go: scanner.l
	golex -o scanner.go scanner.l && gofmt -w scanner.go

