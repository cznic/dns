# Copyright 2009 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

include $(GOROOT)/src/Make.inc

TARG=github.com/cznic/dns/hosts

GOFILES=\
	hosts.go\
	parser.go\
	scanner.go\

CLEANFILES += lex.yy.go y.go parser.tab *~

include $(GOROOT)/src/Make.pkg

scanner.go: scanner.l
	golex -t scanner.l | gofmt > scanner.go

parser.go: parser.y
	goyacc -o parser.go -v parser.tab parser.y
	sed -i -e 's/^func yyParse(yylex yyLexer) int {/func yyParse(yylex *lex) int {/' -e 's|//line.*||' parser.go
	gofmt -w parser.go
