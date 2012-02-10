# Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# blame: jnml, labs.nic.cz

all: scanner.go parser.go

scanner.go: scanner.l
	golex -t scanner.l | gofmt > scanner.go

parser.go: parser.y
	go tool yacc -l -o parser.go -v parser.tab parser.y
	sed -i -e 's/^func yyParse(yylex yyLexer) int {/func yyParse(yylex *lex) int {/' -e 's|//line.*||' parser.go
	gofmt -w parser.go

clean:
	rm -f scanner.go parser.go lex.yy.go parser.tab y.output *~
