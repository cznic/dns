// Copyright (c) 2010 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

package zdb

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"runtime"
	"testing"
	"time"
)

var (
	optKeep  = flag.Bool("keep", false, "do not remove test files")
	optCores = flag.Int("cores", 1, "set GOMAXPROCS with this value")
	optN     = flag.Int("n", 1e6, "Item count for engine benchmarks")
	optBits  = flag.Int("hash", 20, "HashWidth engine benchmarks")
	optPtrs  = flag.Int("ptr", 4, "PtrBytes for engine benchmarks")
	optBench = flag.Bool("b", false, "enable engine \"benchmarks\"")
)

func init() {
	flag.Parse()
	runtime.GOMAXPROCS(*optCores)
}

func BenchmarkHash(b *testing.B) {
	b.StopTimer()
	buf := make([]byte, b.N)
	h := newFNV1a()
	b.SetBytes(1)
	b.StartTimer()
	h.write(buf)
}

func setBits(n uint32) (y int) {
	for n != 0 {
		if n&1 != 0 {
			y++
		}
		n >>= 1
	}
	return
}

func testHash(t *testing.T, w int) {
	const (
		s = "// Copyright (c) 2010 CZ.NIC z.s.p.o. All rights reserved."
	)

	h := newFNV1a()
	h.writeStr(s)
	h0 := h.hash(w)

	bits := 8 * len(s)
	ha := make([]uint32, bits)
	for bit := 0; bit < 8*len(s); bit++ {
		h = newFNV1a()
		b := []byte(s)
		b[bit>>3] ^= 1 << uint(bit&7)
		h.write(b)
		ha[bit] = h.hash(w)
	}
	sum := 0
	for _, h := range ha {
		dif := setBits(h0 ^ h)
		sum += dif
	}
	avg := float64(sum) / float64(len(ha))
	diff := math.Abs(avg - float64(w)/2)
	t.Logf("avg changed bits per a single bit flip: %.2f/%d (delta %.2f)", avg, w, diff)
	if diff > 1.5 {
		t.Fatalf("hash function broken, avg bit flips only %.2f/%d (delta %.2f)", avg, w, diff)
	}
}

func TestHash(t *testing.T) {
	for w := 1; w <= 32; w++ {
		testHash(t, w)
	}
}

func TestDelta(t *testing.T) {
	s := Store{HashWidth: 20, PtrBytes: 4}
	delta, exp := s.delta(), int64(4)*1024*1024+16
	if delta != exp {
		t.Fatal("delta(20, 4): expected %d(0x%x), got %d(0x%x)", exp, exp, delta, delta)
	}

	t.Logf("delta(20, 4): %d(0x%x)", delta, delta)
}

func testNewOpen(t *testing.T, pth string, hashWidth, ptrBytes int) (e error) {
	fn := fmt.Sprintf("%s/zdb-%d-%d", pth, hashWidth, ptrBytes)

	if !*optKeep {
		defer func() {
			os.Remove(fn)
		}()
	}

	s, err := New(fn, hashWidth, ptrBytes)
	if err != nil {
		return err
	}

	if err = s.Close(); err != nil {
		return err
	}

	fi, err := os.Stat(fn)
	if err != nil {
		return err
	}

	t.Logf("%s: %s, HashWidth %d, PtrBytes %d, file size %d(0x%x), s.delta() %d(0x%x)", me(), fn, s.HashWidth, s.PtrBytes, fi.Size, fi.Size, s.delta(), s.delta())

	if s, err = Open(fn); err != nil {
		return err
	}

	defer func() {
		if err := s.Close(); err != nil {
			if e == nil {
				e = err
			}
		}
	}()

	if s.HashWidth != hashWidth {
		return fmt.Errorf("%s: expected HashWidth %d, got %d", me(), hashWidth, s.HashWidth)
	}

	if s.PtrBytes != ptrBytes {
		return fmt.Errorf("%s: expected PtrBytes %d, got %d", me(), ptrBytes, s.PtrBytes)
	}

	return nil
}

func TestNewOpen(t *testing.T) {
	pth, err := ioutil.TempDir("", "zdb-gotest")
	if err != nil {
		t.Fatal(err)
	}

	if !*optKeep {
		defer func() {
			if err = os.RemoveAll(pth); err != nil {
				t.Fatal(err)
			}
		}()
	}

	for hashWidth := 8; hashWidth <= 27; hashWidth++ {
		for ptrBytes := 4; ptrBytes <= 5; ptrBytes++ {
			if err := testNewOpen(t, pth, hashWidth, ptrBytes); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func testSetGet(hashWidth, ptrBytes, n int) (err error) {
	var pth string
	pth, err = ioutil.TempDir("", "zdb-gotest")
	if err != nil {
		return
	}

	if !*optKeep {
		defer func() {
			if e := os.RemoveAll(pth); e != nil {
				if err == nil {
					err = e
				}
			}
		}()
	}

	fn := fmt.Sprintf("%s/zdb-%d-%d", pth, hashWidth, ptrBytes)
	s, err := New(fn, hashWidth, ptrBytes)
	if err != nil {
		return err
	}

	buf := []byte{}
	// value less pass
	for i := 0; i < n; i++ {
		partition := uint16(i & 15)
		ikey := i >> 4
		key := fmt.Sprintf("i%d.example.org", ikey)
		buf = append(buf[:0], key...)
		if err = s.Set(partition, buf, nil); err != nil {
			return
		}
	}
	// overwrite values
	for i := 0; i < n; i++ {
		partition := uint16(i & 15)
		ikey := i >> 4
		key := fmt.Sprintf("i%d.example.org", ikey)
		buf = append(buf[:0], key...)
		if err = s.Set(partition, buf, buf); err != nil {
			return
		}
	}

	if err = s.Close(); err != nil {
		return err
	}

	if s, err = Open(fn); err != nil {
		return err
	}

	defer func() {
		if e := s.Close(); e != nil {
			if err == nil {
				err = e
			}
		}
	}()

	var value []byte
	var ok bool
	for i := 0; i < n; i++ {
		partition := uint16(i & 15)
		ikey := i >> 4
		key := fmt.Sprintf("i%d.example.org", ikey)
		buf = append(buf[:0], key...)
		if value, ok, err = s.Get(partition, buf); err != nil {
			return
		}

		if !ok {
			return fmt.Errorf("%s: partition %d, key %q not found", me(), partition, key)
		}

		if bytes.Compare(value, buf) != 0 {
			return fmt.Errorf("%s: partition %d, key %q, got value %q, expected %q", me(), partition, key, value, key)
		}
	}

	return
}

func TestSetGet(t *testing.T) {
	const N = 1 << 13
	if err := testSetGet(8, 4, N); err != nil {
		t.Fatalf("%s: %s", me(), err)
	}
	if err := testSetGet(8, 5, N); err != nil {
		t.Fatalf("%s: %s", me(), err)
	}
	if err := testSetGet(9, 4, N); err != nil {
		t.Fatalf("%s: %s", me(), err)
	}
	if err := testSetGet(9, 5, N); err != nil {
		t.Fatalf("%s: %s", me(), err)
	}
}

func testBenchGet(hashWidth, ptrBytes, n int) (ns, sz int64, err error) {
	var pth string
	pth, err = ioutil.TempDir("", "zdb-gotest")
	if err != nil {
		return
	}

	defer func() {
		if e := os.RemoveAll(pth); e != nil {
			if err == nil {
				err = e
			}
		}
	}()

	fn := fmt.Sprintf("%s/zdb-%d-%d", pth, hashWidth, ptrBytes)
	var s *Store
	s, err = New(fn, hashWidth, ptrBytes)
	if err != nil {
		return
	}

	buf := []byte{}
	for i := 0; i < n; i++ {
		partition := uint16(i & 15)
		ikey := i >> 4
		key := fmt.Sprintf("i%d.example.org", ikey)
		buf = append(buf[:0], key...)
		if err = s.Set(partition, buf, buf); err != nil {
			return
		}
	}

	if err = s.Close(); err != nil {
		return
	}

	if s, err = Open(fn); err != nil {
		return
	}

	defer func() {
		if e := s.Close(); e != nil {
			if err == nil {
				err = e
			}
		}
	}()

	fi, _ := s.accessor.Stat()
	sz = fi.Size
	ch := make(chan error, *optCores+1)
	chunk := n / *optCores
	if chunk == 0 {
		chunk++
	}
	ns = time.Nanoseconds()
	goroutines := 0
	for from := 0; from < n; from += chunk {
		to := min(from+chunk, n) - 1
		goroutines++
		go func(lo, hi int) {
			var ok bool
			var err error
			var buf []byte
			for i := lo; i < hi; i++ {
				partition := uint16(i & 15)
				ikey := i >> 4
				key := fmt.Sprintf("i%d.example.org", ikey)
				buf = append(buf[:0], key...)
				_, ok, err = s.Get(partition, buf)
				if err != nil {
					ch <- err
					return
				}

				if !ok {
					ch <- fmt.Errorf("%s: partition %d, key %q not found", me(), partition, key)
				}

			}
			ch <- nil
		}(from, to)
	}

	for i := 0; i < goroutines; i++ {
		if err = <-ch; err != nil {
			return
		}
	}

	ns = time.Nanoseconds() - ns
	return
}

func TestBenchGet(t *testing.T) {
	if !*optBench {
		t.Log("Not enabled")
		return
	}

	N := *optN
	ns, sz, err := testBenchGet(*optBits, *optPtrs, N)
	if err != nil {
		t.Fatal(err)
	}

	dt := float64(ns) / 1e9
	v := float64(N) / dt
	T := 1 / v
	t.Logf("%d cores: %d ops in %.4g s, %.0f ops/s, %.4g s/op, file size %d", *optCores, N, dt, v, T, sz)
}
