// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

package hosts

import (
	"testing"
)

func Test0(t *testing.T) {
	const src = `
  
	# parser test

  1.2.3.44 somehost
1.2.3.4 somehost.x
1.2.3.4 somehost.x.y
1.2.3.4 somehost.x.y.z
1.2.3.4 somehost.x.y.z a
1.2.3.4 somehost.x.y.z a b
1.2.3.4 somehost.x.y.z a b c

 1.2.3.4  somehost
     1.2.3.4         somehost.x
1.2.3.4 somehost.x.y
1.2.3.4 somehost.x.y.z
1.2.3.4 somehost.x.y.z a
1.2.3.4 somehost.x.y.z a b
1.2.3.4 somehost.x.y.z a b c

#

 #

# comment

1.2.3.4 so#mehost
1.2.3.4 somehost.x#
1.2.3.4 somehost.x#.y
1.2.3.4 somehost.x.y.z #
1.2.3.4 somehost.x.y.z a #
1.2.3.4 somehost.x.y.z a b # comment
1.2.3.4 somehost.x.y.z a b c


`
	var f File
	if err := f.LoadString("Test0", src); err != nil {
		t.Fatal(10)
	}

	t.Log(&f)
}

func Test1(t *testing.T) {
	var f File
	err := f.Load(Sys)
	if err != nil {
		// Just log, this is not a test fail. 
		// There's no guarantee that this file exists and is valid at the user's site.
		t.Log(err)
		return
	}

	// If loaded OK then show the contens - if in verbose mode
	t.Log(f.String())
}
