# Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# blame: jnml, labs.nic.cz

all: scanner.go

scanner.go: scanner.l
	golex -o scanner.go scanner.l && gofmt -w scanner.go

clean:
	rm -f scanner.go lex.yy.go temp_db y.output *~
