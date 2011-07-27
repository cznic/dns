# Copyright 2009 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

include $(GOROOT)/src/Make.inc

TARG=./resolverexample

GOFILES=\
	resolverexample.go\

include $(GOROOT)/src/Make.cmd

resolverexample.go: resolverexample.l resolver.go
	golex -t resolverexample.l | gofmt > resolverexample.go
