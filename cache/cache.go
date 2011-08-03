// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

// Package cache supports caching of DNS resource records.
package cache

import (
	"github.com/cznic/dns"
	"github.com/cznic/dns/rr"
	"math"
	"strings"
	"sync"
	"time"
)

var secs0 = time.Seconds()

// Secs0 returns the app start time in epoch seconds.
func Secs0() int64 {
	return secs0
}

// Cache is a cache holding DNS RRs. Cache is organized as a dns.Tree.
// Cache handles RR TTLs, expired RRs are removed as encountered.
// Cache is safe for concurrent access.
type Cache struct {
	tree    *dns.Tree
	rwm     sync.RWMutex
	pending map[string]bool // removals
}

// New returns a newly created Cache.
func New() *Cache {
	return &Cache{tree: dns.NewTree(), pending: map[string]bool{}}
}

// Enum will enumerate Cache. Writers are blocked until Enum finishes.
func (c *Cache) Enum(root string, handler func([]string, rr.Bytes) bool) {
	c.rwm.RLock()         // R++
	defer c.rwm.RUnlock() // R--

	c.tree.Enum(root, func(path []string, data interface{}) bool {
		switch x := data.(type) {
		case rr.Bytes:
			return handler(path, x)
		}

		return true
	})
}

// Add will put or append RRs r into the cache owned by their rr.RR.Name.
// RRs TTLs are interpreted as being relative to current time.
func (c *Cache) Add(rrs ...rr.RRs) {
	owners := map[string]rr.RRs{}
	for _, recs := range rrs {
		for _, rec := range recs {
			nm := strings.ToLower(rec.Name)
			owners[nm] = append(owners[nm], rec)
		}
	}
	for nm, rrs := range owners {
		c.add(nm, rrs)
	}
}

func (c *Cache) add(name string, rrs rr.RRs) {
	newparts := rrs.Partition(true)
	if tidy(0, newparts) && len(newparts) == 0 { // nothing left to add
		return
	}

	now := time.Seconds()
	for _, part := range newparts {
		for _, rec := range part {
			rec.TTL = int32(now - secs0 + int64(rec.TTL))
		}
	}

	c.rwm.Lock()         // W++
	defer c.rwm.Unlock() // W--

	if oldparts, hit, _ := c.get0(name); hit {
		newparts.SetAdd(oldparts)
	}
	c.tree.Put(name, newparts.Join().Pack())
}

func tidy(dt int64, parts rr.Parts) (expired bool) {
	for typ, part := range parts {
		min := int32(math.MaxInt32)
		for _, v := range part {
			if ttl := v.TTL; ttl < min {
				min = ttl
			}
		}
		if int64(min) <= dt { // expired
			parts[typ] = nil, false
			expired = true
		}
	}
	return
}

func (c *Cache) get0(name string) (parts rr.Parts, hit, expired bool) {
	var item rr.Bytes
	if item, hit = c.tree.Get(name).(rr.Bytes); hit {
		parts = item.Unpack().Partition(false)
		expired = tidy(time.Seconds()-secs0, parts)
		hit = len(parts) != 0
	}
	return
}

func (c *Cache) get(name string) (parts rr.Parts, hit bool) {
	expired := false
	if parts, hit, expired = c.get0(name); hit {
		if expired { // Schedule removal
			go func() {
				c.rwm.Lock()         // W++
				defer c.rwm.Unlock() // W--

				if c.pending[name] { // P
					return
				}

				// !P && W
				c.pending[name] = true                            // P++
				defer func() { c.pending[name] = false, false }() // P--

				if parts, hit, expired := c.get0(name); hit && expired {
					if len(parts) != 0 {
						c.tree.Put(name, parts.Join().Pack())
						return
					}

					c.tree.Delete(name)
				}
			}()
		}
	}

	return
}

// Get will return rrs and true if non expired cached RRs owned by name are present in the cache.
// If Get encounters expired RRs they are scheduled for removal and not returned.
func (c *Cache) Get(name string) (rrs rr.RRs, hit bool) {
	c.rwm.RLock()         // R++
	defer c.rwm.RUnlock() // R--

	var parts rr.Parts
	now := time.Seconds()
	if parts, hit = c.get(name); hit {
		rrs = parts.Join()
		for _, v := range rrs {
			v.TTL = int32(int64(v.TTL) + secs0 - now)
		}
	}

	return
}
