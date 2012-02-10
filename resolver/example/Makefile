# Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# blame: jnml, labs.nic.cz

all: resolverexample.go

resolverexample.go: resolverexample.l
	golex -t resolverexample.l | gofmt > resolverexample.go

clean:
	rm -f resolverexample.go *~

nuke: clean
	rm -f example
