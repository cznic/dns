# Copyright 2009 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

include $(GOROOT)/src/Make.inc

TARG=github.com/cznic/dns/resolver

GOFILES=\
	resolver.go\

CLEANFILES+=resolverexample.go resolverexample lex.yy.go *~

include $(GOROOT)/src/Make.pkg

resolverexample: resolverexample.l resolver.go
	make install clean && make -f resolverexample.make
