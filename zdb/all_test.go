// Copyright (c) 2010 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz


package zdb

import (
	"bytes"
	"github.com/cznic/mathutil"
	"github.com/cznic/fileutil"
	"github.com/cznic/fileutil/storage"
	"flag"
	"fmt"
	"math"
	"os"
	"runtime"
	"testing"
	"time"
)

const fn = "test.tmp"
//const fn = "/media/flash2GB/test.tmp"


var (
	cacheFlag      = flag.Bool("cache", false, "use storage.Cache")
	cacheTotalFlag = flag.Int64("cachemax", 1<<25, "cache total bytes")
	fadviseFlag    = flag.Bool("fadvise", false, "hint kernel about random file access")
	fFlag          = flag.String("f", "test.tmp", "test file name")
	nFlag          = flag.Int("n", 1, "test N")
)

func init() {
	runtime.GOMAXPROCS(3)
	flag.Parse()
}

func dbnew(fn string) (s *Store, err os.Error) {
	var store storage.Accessor

	if store, err = storage.NewFile(fn, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0666); err != nil {
		return
	}

	if *fadviseFlag {
		if err = fileutil.Fadvise(store.(*os.File), 0, 0, fileutil.POSIX_FADV_RANDOM); err != nil {
			return
		}
	}

	if *cacheFlag {
		if store, err = storage.NewCache(store, *cacheTotalFlag, nil); err != nil {
			return
		}
	}

	return New(store, true)
}

func dbopen(fn string) (s *Store, err os.Error) {
	var store storage.Accessor

	if store, err = storage.NewFile(fn, os.O_RDWR, 0666); err != nil {
		return
	}

	if *fadviseFlag {
		if err = fileutil.Fadvise(store.(*os.File), 0, 0, fileutil.POSIX_FADV_RANDOM); err != nil {
			return
		}
	}

	if *cacheFlag {
		if store, err = storage.NewCache(store, *cacheTotalFlag, nil); err != nil {
			return
		}
	}

	return Open(store, true)
}

func bitcount(n uint) (y int) {
	for n != 0 {
		if n&1 != 0 {
			y++
		}
		n >>= 1
	}
	return
}

func TestHash0(t *testing.T) {
	const s = "// Copyright (c) 2010 CZ.NIC z.s.p.o. All rights reserved."

	m := map[uint]int{}
	h0 := hash([]byte(s))
	m[h0] = 1

	bits := 8 * len(s)
	ha := make([]uint, bits)
	for bit := 0; bit < 8*len(s); bit++ {
		b := []byte(s)
		b[bit>>3] ^= 1 << uint(bit&7)
		h := hash(b)
		m[h] += 1
		ha[bit] = h
	}
	sum := 0
	for _, h := range ha {
		x := h0 ^ h
		dif := bitcount(x)
		sum += dif
	}
	t.Logf("avg changed bits per a single bit flip: %.2f/%.2f", float64(sum)/float64(len(ha)), math.Log2(29*31*37*41*43))
}

func BenchmarkHash(b *testing.B) {
	b.StopTimer()
	s := make([]byte, b.N)
	b.SetBytes(1)
	b.StartTimer()
	_ = hash(s)
}

func TestHash1(t *testing.T) {
	for _, s := range []string{"b", "c", "ba", "ca", "bat", "cat", "tab", "tac"} {
		t.Logf("%5q %08x\n", s, hash([]byte(s)))
	}
}

var rndsg *mathutil.FC32

func init() {
	var err os.Error
	rndsg, err = mathutil.NewFC32(math.MinInt32, math.MaxInt32, true)
	if err != nil {
		panic(err)
	}
}

func rnds(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rndsg.Next())
	}
	return string(b)
}

// check collision immunity of a single bit flip
func checkflip(s string) (cnt int) {
	m := map[uint]bool{}
	h0 := hash([]byte(s))
	m[h0] = true
	for bit := 0; bit < 8*len(s); bit++ {
		b := []byte(s)
		b[bit>>3] ^= 1 << uint(bit&7)
		h := hash(b)
		if m[h] {
			cnt++
		}
		m[h] = true
	}
	return
}

//func TestBitFlip(t *testing.T) {
//if testing.Short() {
//t.Log("TestBitFlip skipped")
//return
//}

//n := 1
//for {
//t0 := time.Nanoseconds()
//if cnt := checkflip(rnds(n)); cnt != 0 {
//t.Logf("failed bit flips %7d/%7d (%8.6g%%)\n", cnt, 8*n, 100*float64(cnt)/(8*float64(n)))
//}
//t := time.Nanoseconds() - t0
//if t > 2e9 || n == 1<<16 {
//break
//}
//n *= 2
//}
//}


func TestZip(t *testing.T) {
	x := zip(1)
	for bits := 1; bits <= 8*8; bits++ {
		b := make([]byte, 0, 10)
		x.put(&b)
		bytes := (bits + 6) / 7
		if n := len(b); n != bytes {
			t.Fatalf("10 %#x: %d %d [% x]", x, bytes, n, b)
		}

		var y zip
		if n := y.get(b); n != bytes {
			t.Fatal(20, bytes, n)
		}

		if x != y {
			t.Fatalf("30 %#x %#x", y, x)
		}

		x <<= 1
		if bits&1 != 1 {
			x |= 1
		}
	}
}

func TestZip2(t *testing.T) {
	x := zip(1)
	for bits := 1; bits <= 8*8; bits++ {
		b := make([]byte, 10)
		nb := x.put2(b)
		bytes := (bits + 6) / 7
		if nb != bytes {
			t.Fatalf("10 %#x: %d %d [% x]", x, nb, bytes, b)
		}

		var y zip
		if n := y.get(b); n != bytes {
			t.Fatal(20, bytes, n)
		}

		if x != y {
			t.Fatalf("30 %#x %#x", y, x)
		}

		x <<= 1
		if bits&1 == 1 {
			x |= 1
		}
	}
}

func BenchmarkZip(b *testing.B) {
	b.StopTimer()
	b.SetBytes(10)
	buf := make([]byte, 10)
	x := zip(0xfedcba9876543210)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		buf := buf[:0]
		x.put(&buf)
	}
}

func BenchmarkZip2(b *testing.B) {
	b.StopTimer()
	b.SetBytes(10)
	buf := make([]byte, 10)
	x := zip(0xfedcba9876543210)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		x.put2(buf)
	}
}

func BenchmarkUnZip(b *testing.B) {
	b.StopTimer()
	b.SetBytes(10)
	buf := make([]byte, 10)
	zip(0xfedcba9876543210).put(&buf)
	var y zip
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		y.get(buf)
	}
}

func sreverse(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func TestMapGet0(t *testing.T) {
	db, err := dbnew(fn)
	if err != nil {
		t.Fatal(10, err)
	}

	defer func() {
		ec := db.Close()
		er := os.Remove(fn)
		if ec != nil {
			t.Fatal(20, ec)
		}

		if er != nil {
			t.Fatal(30, er)
		}
	}()

	m := db.RootMap
	keys := []string{"", "a", "ab", "ba", "foo", "bar"}
	for _, key := range keys {
		v, ok, err := m.Get(nil)
		if err != nil {
			t.Fatal(key, 40, err)
		}

		if ok {
			t.Fatal(key, 50)
		}

		if len(v) != 0 {
			t.Fatal(key, 60)
		}
	}

	for i, key := range keys {
		t.Logf("setting key %q", key)
		err := m.Set([]byte(key), []byte(sreverse(key)))
		if err != nil {
			t.Fatal(key, 70, err)
		}

		for j, rkey := range keys {
			t.Logf("getting rkey %q", rkey)
			v, ok, err := m.Get([]byte(rkey))
			if err != nil {
				t.Fatal(key, rkey, 80, err)
			}

			if ok != (j <= i) {
				t.Fatal(key, rkey, 90, string(v), ok)
			}

			if !ok {
				continue
			}

			//t.Logf("Get(%q) == %q", rkey, v)
			exp := sreverse(rkey)
			if string(v) != exp {
				t.Fatalf("100: key %q rkey %q v %q exp %q", key, rkey, string(v), exp)
			}
		}
	}

	if err = db.Close(); err != nil {
		t.Fatal(110, err)
	}

	if db, err = dbopen(fn); err != nil {
		t.Fatal(120, err)
	}

	t.Log("[[[ reopened ]]]")
	m = db.RootMap

	for _, rkey := range keys {
		t.Logf("(re)getting rkey %q", rkey)
		v, ok, err := m.Get([]byte(rkey))
		if err != nil {
			t.Fatal(rkey, 130, err)
		}

		if !ok {
			t.Fatal(rkey, 140, string(v))
		}

		t.Logf("Get(%q) == %q", rkey, v)
		exp := sreverse(rkey)
		if string(v) != exp {
			t.Fatalf("150: rkey %q v %q exp %q", rkey, string(v), exp)
		}
	}
}

var uconflict [2]string // upper 13/26 bit hash conflict


func init() {
	b := []byte{}
	m := map[uint16]string{}
	rng, err := mathutil.NewFC32(math.MinInt32, math.MaxInt32, true)
	if err != nil {
		panic(err)
	}

	n := 0
	for {
		b = append(b, byte(rng.Next()))
		h := uint16(hash(b) >> 13)
		if _, ok := m[h]; ok { // conflict
			uconflict[0] = m[h]
			uconflict[1] = string(b)
			return
		}
		m[h] = string(b)
		n++
	}
}

var conflict [2]string // full 26 bit hash conflict


func init() {
	b := []byte{}
	m := map[uint]string{}
	rng, err := mathutil.NewFC32(math.MinInt32, math.MaxInt32, true)
	if err != nil {
		panic(err)
	}

	n := 0
	for {
		b = append(b, byte(rng.Next()))
		s := string(b)
		h := hash(b)
		if _, ok := m[h]; ok { // conflict
			conflict[0] = m[h]
			conflict[1] = s
			return
		}
		m[h] = s
		n++
	}
}

func testMapSetConflict(t *testing.T, keys []string) {
	for i, s := range keys {
		t.Logf("%d: %s %d", i, shortq(s), len(s))
	}

	db, err := dbnew(fn)
	if err != nil {
		t.Fatal(10, err)
	}

	defer func() {
		ec := db.Close()
		er := os.Remove(fn)
		if ec != nil {
			t.Fatal(20, ec)
		}

		if er != nil {
			t.Fatal(30, er)
		}
	}()

	m := db.RootMap

	exp := []string{"conflict-A", "conflict-B"}
	for i := 0; i < 2; i++ {
		t.Log("pass", i)
		for i, key := range keys {
			err = m.Set([]byte(key), []byte(exp[i]))
			if err != nil {
				t.Fatal(40, i, err)
			}
		}

		for i, key := range keys {
			v, ok, err := m.Get([]byte(key))
			if err != nil {
				t.Fatal(45, i)
			}

			if !ok {
				t.Fatal(50, i)
			}

			if g, e := string(v), exp[i]; g != e {
				t.Fatalf("60 %d\nkey %s %d\ngot %s %d\nexp %s %d", i, shortq(key), len(key), shortq(g), len(g), shortq(e), len(e))
			}
		}

		if err = db.Close(); err != nil {
			t.Fatal(70, err)
		}

		if db, err = dbopen(fn); err != nil {
			t.Fatal(80, err)
		}

		m = db.RootMap

		for i, key := range keys {
			v, ok, err := m.Get([]byte(key))
			if err != nil {
				t.Fatal(145, i)
			}

			if !ok {
				t.Fatal(150, i)
			}

			if g, e := string(v), exp[i]; g != e {
				t.Fatal(160, i, g, e)
			}
		}
		exp[0], exp[1] = exp[1], exp[0]
	}
}

func shortq(s string) string {
	x := fmt.Sprintf("%q", s)
	if len(x) < 64 {
		return x
	}
	return x[:30] + "..." + x[len(x)-30:]
}

func TestMapSetConflict(t *testing.T) {
	t.Log("uconflict 1")
	testMapSetConflict(t, uconflict[:])
	t.Log("uconflict 2")
	uconflict[0], uconflict[1] = uconflict[1], uconflict[0]
	testMapSetConflict(t, uconflict[:])
	t.Log("conflict 1")
	testMapSetConflict(t, conflict[:])
	conflict[0], conflict[1] = conflict[1], conflict[0]
	t.Log("conflict 2")
	testMapSetConflict(t, conflict[:])
}

func TestMapSetGet(t *testing.T) {
	const (
		n = 1000
	)

	db, err := dbnew(fn)
	if err != nil {
		t.Fatal(10, err)
	}

	defer func() {
		ec := db.Close()
		er := os.Remove(fn)
		if ec != nil {
			t.Fatal(20, ec)
		}

		if er != nil {
			t.Fatal(30, er)
		}
	}()

	m := db.RootMap
	km := make(map[string][]byte, n)
	ops := 0

	for i := 0; i < n; i++ {
		km[rnds(i%64)] = []byte(rnds(i % 256))
	}

	t.Logf("%d keys", len(km))

	for key, value := range km {
		if err = m.Set([]byte(key), value); err != nil {
			t.Fatal(40, err)
		}
		ops++
	}

	for key, value := range km {
		v, ok, err := m.Get([]byte(key))
		if err != nil {
			t.Fatal(50, err)
		}

		if !ok {
			t.Fatal(60)
		}

		if !bytes.Equal(v, value) {
			t.Fatalf("70\nkey % x\ngot [% x]\nexp [% x]", key, v, value)
		}
		ops++
	}

	if err = db.Close(); err != nil {
		t.Fatal(70, err)
	}

	if db, err = dbopen(fn); err != nil {
		t.Fatal(80, err)
	}

	m = db.RootMap

	for key, value := range km {
		v, ok, err := m.Get([]byte(key))
		if err != nil {
			t.Fatal(150, err)
		}

		if !ok {
			t.Fatal(160)
		}

		if !bytes.Equal(v, value) {
			t.Fatalf("170\nkey % x\ngot [% x]\nexp [% x]", key, v, value)
		}
		ops++
	}

	i := 0
	for key := range km {
		km[key] = []byte(rnds(i % 256))
		i++
	}

	for key, value := range km {
		if err = m.Set([]byte(key), value); err != nil {
			t.Fatal(240, err)
		}
		ops++
	}

	for key, value := range km {
		v, ok, err := m.Get([]byte(key))
		if err != nil {
			t.Fatal(350, err)
		}

		if !ok {
			t.Fatal(360)
		}

		if !bytes.Equal(v, value) {
			t.Fatalf("370\nkey % x\ngot [% x]\nexp [% x]", key, v, value)
		}
		ops++
	}

	if err = db.Close(); err != nil {
		t.Fatal(470, err)
	}

	if db, err = dbopen(fn); err != nil {
		t.Fatal(480, err)
	}

	m = db.RootMap

	for key, value := range km {
		v, ok, err := m.Get([]byte(key))
		if err != nil {
			t.Fatal(550, err)
		}

		if !ok {
			t.Fatal(560)
		}

		if !bytes.Equal(v, value) {
			t.Fatalf("570\nkey % x\ngot [% x]\nexp [% x]", key, v, value)
		}
		ops++
	}
	fi, err := db.Store.File().Accessor().Stat()
	if err != nil {
		t.Fatal(900, err)
	}

	t.Log(ops, "ops, size", fi.Size, "b/key", fi.Size/int64(len(km)))
}

/*
--- PASS: zdb.TestMapSetGet2 (0.29 seconds)
	1009 keys
	2018 ops, size 27 730 656 b/key 27483 read time 0.050217 read op time 4.976907829534192e-05 conflicts 0

--- PASS: zdb.TestMapSetGet2 (0.61 seconds)
	2017 keys
	4034 ops, size 54 057 136 b/key 26800 read time 0.107117 read op time 5.310708973723352e-05 conflicts 0

--- PASS: zdb.TestMapSetGet2 (1.22 seconds)
	4026 keys
	8052 ops, size 98 545 008 b/key 24477 read time 0.232462 read op time 5.774018877297566e-05 conflicts 0

--- PASS: zdb.TestMapSetGet2 (2.45 seconds)
	8042 keys
	16084 ops, size 172 494 576 b/key 21449 read time 0.509863 read op time 6.340002486943546e-05 conflicts 0

--- PASS: zdb.TestMapSetGet2 (17.39 seconds)
	16039 keys
	32078 ops, size 270 544 336 b/key 16867 read time 1.39448 read op time 8.694307625163663e-05 conflicts 0

--- PASS: zdb.TestMapSetGet2 (37.32 seconds)
	31963 keys
	63926 ops, size 377 905 616 b/key 11823 read time 3.317399 read op time 0.00010378872446265995 conflicts 0

--- PASS: zdb.TestMapSetGet2 (98.00 seconds)
	63732 keys
	127464 ops, size 479 755 728 b/key 7527 read time 7.532085 read op time 0.00011818372246281303 conflicts 0

--- PASS: zdb.TestMapSetGet2 (274.01 seconds)
	127193 keys
	254386 ops, size 581 164 208 b/key 4569 read time 15.638812 read op time 0.00012295340152366875 conflicts 0

--- PASS: zdb.TestMapSetGet2 (643.26 seconds)
	254071 keys
	508142 ops, size 671 132 240 b/key 2641 read time 31.805395 read op time 0.00012518309842524334 conflicts 0

--- PASS: zdb.TestMapSetGet2 (1302.43 seconds)
	507629 keys
	1015258 ops, size 760 574 672 b/key 1498 read time 66.074066 read op time 0.00013016211839749108 conflicts 0

************************************
|                                  |
|   hashindex handling rewrite     |
|                                  |
************************************

--- PASS: zdb.TestMapSetGet2 (0.25 seconds)
	1009 keys in 0.017123
	write t 0.207297
	2018 ops, size 54 489 600 b/key 54003 read time 0.006437 read op time 6.3795837462834486e-06

--- PASS: zdb.TestMapSetGet2 (0.49 seconds)
	2016 keys in 0.033366
	write t 0.400473
	4032 ops, size 101 984 384 b/key 50587 read time 0.014596 read op time 7.240079365079365e-06

--- PASS: zdb.TestMapSetGet2 (0.94 seconds)
	4029 keys in 0.067302
	write t 0.763548
	8058 ops, size 182 518 896 b/key 45301 read time 0.033876 read op time 8.408041697691735e-06

--- PASS: zdb.TestMapSetGet2 (2.89 seconds)
	8044 keys in 0.131221
	write t 1.331721
	16088 ops, size 294 142 208 b/key 36566 read time 0.055972 read op time 6.958229736449528e-06

--- PASS: zdb.TestMapSetGet2 (5.89 seconds)
	16042 keys in 0.27085
	write t 2.392914
	32084 ops, size 405 533 952 b/key 25279 read time 0.135083 read op time 8.420583468395463e-06

--- PASS: zdb.TestMapSetGet2 (27.17 seconds)
	31971 keys in 0.546333
	write t 26.164614
	63942 ops, size 466 267 792 b/key 14584 read time 0.244486 read op time 7.647117700416003e-06

--- PASS: zdb.TestMapSetGet2 (16.39 seconds)
	63728 keys in 1.190854
	write t 9.566216
	127456 ops, size 480 859 760 b/key 7545 read time 0.474918 read op time 7.452265879989957e-06

--- PASS: zdb.TestMapSetGet2 (37.67 seconds)
	127189 keys in 2.564967
	write t 23.909262
	254378 ops, size 491 917 856 b/key 3867 read time 1.025034 read op time 8.059140334462885e-06

--- PASS: zdb.TestMapSetGet2 (339.20 seconds)
	254065 keys in 4.62331
	write t 332.772852
	508130 ops, size 513 794 288 b/key 2022 read time 1.66626 read op time 6.5584004093440655e-06

--- PASS: zdb.TestMapSetGet2 (644.64 seconds)
	507625 keys in 9.22354
	write t 567.048071
	1015250 ops, size 557 530 464 b/key 1098 read time 3.790771 read op time 7.4676601822211276e-06

********************************
|                              |
|   introduce Map.Prealloc     |
|                              |
********************************

--- PASS: zdb.TestMapSetGet2 (5.86 seconds)
	1 keys in 4e-06
	write t 5.4e-05
	2 ops, size 470 004 528 b/key 470004528 read time 9e-06 read op time 9e-06

--- PASS: zdb.TestMapSetGet2 (2.60 seconds)
	2 keys in 6e-06
	write t 8.3e-05
	4 ops, size 470 004 544 b/key 235002272 read time 1.4e-05 read op time 7e-06

--- PASS: zdb.TestMapSetGet2 (2.89 seconds)
	4 keys in 1.1e-05
	write t 0.000225
	8 ops, size 470 004 576 b/key 117501144 read time 3.1e-05 read op time 7.75e-06

--- PASS: zdb.TestMapSetGet2 (8.80 seconds)
	8 keys in 1.7e-05
	write t 0.844069
	16 ops, size 470 004 656 b/key 58750582 read time 8.1e-05 read op time 1.0125e-05

--- PASS: zdb.TestMapSetGet2 (5.87 seconds)
	16 keys in 3.6e-05
	write t 0.000606
	32 ops, size 470 004 928 b/key 29375308 read time 7.3e-05 read op time 4.5625e-06

--- PASS: zdb.TestMapSetGet2 (10.62 seconds)
	32 keys in 0.000115
	write t 1.038373
	64 ops, size 470 005 856 b/key 14687683 read time 0.000179 read op time 5.59375e-06

--- PASS: zdb.TestMapSetGet2 (5.62 seconds)
	64 keys in 0.000414
	write t 0.002636
	128 ops, size 470 009 248 b/key 7343894 read time 0.000311 read op time 4.859375e-06

--- PASS: zdb.TestMapSetGet2 (5.88 seconds)
	127 keys in 0.001294
	write t 0.004355
	254 ops, size 470 018 064 b/key 3700929 read time 0.00063 read op time 4.960629921259843e-06

--- PASS: zdb.TestMapSetGet2 (13.21 seconds)
	253 keys in 0.004042
	write t 1.336888
	506 ops, size 470 047 920 b/key 1857896 read time 0.001554 read op time 6.142292490118577e-06

--- PASS: zdb.TestMapSetGet2 (6.24 seconds)
	505 keys in 0.007977
	write t 0.041157
	1010 ops, size 470 091 120 b/key 930873 read time 0.004217 read op time 8.350495049504951e-06

--- PASS: zdb.TestMapSetGet2 (10.11 seconds)
	1009 keys in 0.015644
	write t 2.966222
	2018 ops, size 470 177 520 b/key 465983 read time 0.007103 read op time 7.0396432111000994e-06

--- PASS: zdb.TestMapSetGet2 (9.74 seconds)
	2016 keys in 0.038319
	write t 2.621219
	4032 ops, size 470 350 304 b/key 233308 read time 0.011109 read op time 5.510416666666667e-06

--- PASS: zdb.TestMapSetGet2 (10.74 seconds)
	4029 keys in 0.065238
	write t 2.425928
	8058 ops, size 470 695 536 b/key 116826 read time 0.02871 read op time 7.125837676842889e-06

--- PASS: zdb.TestMapSetGet2 (7.15 seconds)
	8044 keys in 0.128635
	write t 0.289516
	16088 ops, size 471 384 608 b/key 58600 read time 0.0534 read op time 6.638488314271507e-06

--- PASS: zdb.TestMapSetGet2 (11.80 seconds)
	16042 keys in 0.29491
	write t 3.368763
	32084 ops, size 472 759 872 b/key 29470 read time 0.122617 read op time 7.64349831691809e-06

--- PASS: zdb.TestMapSetGet2 (12.94 seconds)
	31971 keys in 0.545369
	write t 8.12971
	63942 ops, size 475 502 752 b/key 14872 read time 0.250041 read op time 7.82086891245191e-06

--- PASS: zdb.TestMapSetGet2 (121.44 seconds)
	63728 keys in 1.10306
	write t 3.337489
	127456 ops, size 480 974 480 b/key 7547 read time 0.514476 read op time 8.072997740396687e-06

--- PASS: zdb.TestMapSetGet2 (152.43 seconds)
	127189 keys in 2.239808
	write t 139.902059
	254378 ops, size 491 917 856 b/key 3867 read time 0.981441 read op time 7.716398430681899e-06

--- PASS: zdb.TestMapSetGet2 (409.14 seconds)
	254065 keys in 4.570327
	write t 304.6021
	508130 ops, size 513 794 288 b/key 2022 read time 2.008983 read op time 7.907358353177336e-06

--- PASS: zdb.TestMapSetGet2 (727.45 seconds)
	507625 keys in 9.042953
	write t 698.114733
	1015250 ops, size 557 530 464 b/key 1098 read time 3.473857 read op time 6.843352868751539e-06

--- PASS: zdb.TestMapSetGet2 (1136.03 seconds)
	1014135 keys in 18.280534
	write t 1107.203888
	2028270 ops, size 644 945 536 b/key 635 read time 7.538248 read op time 7.4331800006902435e-06

--- PASS: zdb.TestMapSetGet2 (4207.26 seconds)
	2024784 keys in 38.177359
	write t 3896.401267
	4049568 ops, size 819 517 328 b/key 404 read time 264.245819 read op time 0.0001305056830753305

*/
func TestMapSetGet2(t *testing.T) {
	const (
		n = 1 << 10
	)

	db, err := dbnew(fn)
	if err != nil {
		t.Fatal(10, err)
	}

	defer func() {
		db.accessor.Truncate(0)
		ec := db.Close()
		er := os.Remove(fn)
		if ec != nil {
			t.Fatal(20, ec)
		}

		if er != nil {
			t.Fatal(30, er)
		}
	}()

	m := db.RootMap

	km := make(map[string][]byte, n)
	ops := 0

	t0 := time.Nanoseconds()
	for i := 0; i < n; i++ {
		km[rnds(i%64)] = []byte(rnds(i % 256))
	}
	t1 := float64(time.Nanoseconds()-t0) / 1e9

	t.Logf("%d keys in %g", len(km), t1)

	t0 = time.Nanoseconds()
	for key, value := range km {
		if err = m.Set([]byte(key), value); err != nil {
			t.Fatal(40, err)
		}
		ops++
	}
	t1 = float64(time.Nanoseconds()-t0) / 1e9
	t.Log("write t", t1)

	println("\nwrite done")
	//println("time sync && sudo sh -c \"echo 3 > /proc/sys/vm/drop_caches\", <ctrl-d> to continue")
	//gosh()
	runtime.GC()

	t0 = time.Nanoseconds()
	for key, value := range km {
		v, ok, err := m.Get([]byte(key))
		if err != nil {
			t.Fatal(50, err)
		}

		if !ok {
			t.Fatal(60)
		}

		if !bytes.Equal(v, value) {
			t.Fatalf("70\nkey % x\ngot [% x]\nexp [% x]", key, v, value)
		}
		ops++
	}
	t1 = float64(time.Nanoseconds()-t0) / 1e9

	fi, err := db.accessor.Stat()
	if err != nil {
		t.Fatal(900, err)
	}

	t.Log(
		ops, "ops, size", fi.Size,
		"b/key", fi.Size/int64(len(km)),
		"read time", t1,
		"read op time", t1/float64(len(km)),
	)
}

//func gosh() {
//shbin, err := exec.LookPath("sh")
//if err != nil {
//panic(err)
//}

//cmd, err := exec.Run(shbin, nil, nil, "", exec.PassThrough, exec.PassThrough, exec.MergeWithStdout)
//msg, err := cmd.Wait(0)
//if err != nil {
//panic(err)
//}
//if msg.ExitStatus() != 0 {
//panic(msg)
//}
//}


func TestMapSetGet3(t *testing.T) {
	n := *nFlag

	db, err := dbnew(fn)
	if err != nil {
		t.Fatal(10, err)
	}

	defer func() {
		db.accessor.Truncate(0)
		ec := db.Close()
		er := os.Remove(fn)
		if ec != nil {
			t.Fatal(20, ec)
		}

		if er != nil {
			t.Fatal(30, er)
		}
	}()

	m := db.RootMap

	km := make(map[string]bool, n)
	ops := 0

	perc := 1
	if n > 1000 {
		perc = n / 1000
	}
	t0 := time.Nanoseconds()
	for i := 0; i < n; i++ {
		km[rnds(i%64)] = true
	}
	t1 := float64(time.Nanoseconds()-t0) / 1e9

	//t.Logf("%d keys in %g", len(km), t1)

	t0 = time.Nanoseconds()
	i := 0
	for key := range km {
		if err = m.Set([]byte(key), []byte(rnds(i%256))); err != nil {
			t.Fatal(40, err)
		}
		ops++
		i++
		if i%perc == 0 {
			print("w ", i, "/", n, "                    \r")
		}
	}
	t1 = float64(time.Nanoseconds()-t0) / 1e9
	//t.Log("write t", t1)
	println("\nwrite t", int(t1))

	i = 0
	t0 = time.Nanoseconds()
	for key := range km {
		_, ok, err := m.Get([]byte(key))
		if err != nil {
			t.Fatal(50, err)
		}

		if !ok {
			t.Fatal(60)
		}

		ops++
		i++
		if i%perc == 0 {
			print("r ", i, "/", n, "                    \r")
		}
	}
	t1 = float64(time.Nanoseconds()-t0) / 1e9
	println("\ndone")

	fi, err := db.accessor.Stat()
	if err != nil {
		t.Fatal(900, err)
	}

	t.Log(
		len(km), "keys, size", fi.Size,
		"b/key", fi.Size/int64(len(km)),
		"read time", t1,
		"read op time", t1/float64(len(km)),
		int(float64(len(km))/t1), "keys/s",
	)
}

func k16(k []byte, n int) []byte {
	for i := 0; i < 16; i++ {
		k[i] = byte(n & 3)
		n >>= 2
	}
	return k
}

func TestMapSetGet4(t *testing.T) {
	n := *nFlag

	rng, err := mathutil.NewFC32(0, n-1, true)
	if err != nil {
		t.Fatal(5, err)
	}

	db, err := dbnew(*fFlag)
	if err != nil {
		t.Fatal(10, err)
	}

	defer func() {
		et := db.accessor.Truncate(0)
		ec := db.Close()
		er := os.Remove(*fFlag)
		if et != nil {
			t.Fatal(15, et)
		}

		if ec != nil {
			t.Fatal(20, ec)
		}

		if er != nil {
			t.Fatal(30, er)
		}
	}()

	m := db.RootMap

	perc := 1
	if n > 1000 {
		perc = n / 1000
	}

	key := make([]byte, 16)
	value := make([]byte, 134)
	t0 := time.Nanoseconds()
	for i := 0; i < n; i++ {
		if err = m.Set(k16(key, i), value); err != nil {
			t.Fatal(40, err)
		}
		if i%perc == 0 {
			print("w ", i, "/", n, "                    \r")
		}
	}
	t1 := float64(time.Nanoseconds()-t0) / 1e9
	println("\nwrite t", int(t1))

	//if err = db.accessor.Sync(); err != nil {
	//t.Fatal(45, err)
	//}
	//println("Sync()")

	t0 = time.Nanoseconds()
	for i := 0; i < n; i++ {
		_, ok, err := m.Get(k16(key, rng.Next()))
		if err != nil {
			t.Fatal(50, err)
		}

		if !ok {
			t.Fatal(60)
		}

		if i%perc == 0 {
			print("r ", i, "/", n, "                    \r")
		}
	}
	t1 = float64(time.Nanoseconds()-t0) / 1e9
	println("\ndone")

	fi, err := db.accessor.Stat()
	if err != nil {
		t.Fatal(900, err)
	}

	t.Logf("%10d x (16+134)B, file %11d B, %7d B/key, read T %6.2g s, %8d keys/s",
		n, fi.Size, fi.Size/int64(n), t1, int(float64(n)/t1),
	)
}

func TestWrite100M(t *testing.T) {
	n := *nFlag

	db, err := dbnew(*fFlag)
	if err != nil {
		t.Fatal(10, err)
	}

	defer func() {
		ec := db.Close()
		if ec != nil {
			t.Fatal(20, ec)
		}
	}()

	m := db.RootMap

	perc := 1
	if n > 1000 {
		perc = n / 1000
	}

	key := make([]byte, 16)
	value := make([]byte, 134)
	t0 := time.Nanoseconds()
	st0 := time.SecondsToLocalTime(t0 / 1e9).Format(time.Kitchen)
	dt, eta := int64(0), int64(0)
	for i := 0; i < n; i++ {
		if err = m.Set(k16(key, i), value); err != nil {
			t.Fatal(40, err)
		}
		if i != 0 && i%perc == 0 {
			ut := time.Nanoseconds() - t0
			q := float64(i) / float64(n)
			rt := float64(ut)/q - float64(ut)
			eta0 := eta
			eta = t0 + int64(rt)
			dt0 := dt
			dt = eta - eta0
			ddt := dt - dt0
			fi, err := db.accessor.Stat()
			if err != nil {
				t.Fatal(42, err)
			}

			mb := fi.Size / (1 << 20)
			uts := ut / 1e9
			v := float64(mb) / float64(uts)
			fmt.Printf("w %d/%d %d MB (%8.1f MB/S) %s+%s eta %s (%s %s)\n",
				i, n, mb, v, st0, dts(ut), time.SecondsToLocalTime(eta/1e9).Format(time.RFC1123),
				dts(dt), dts(ddt),
			)
		}
	}
	t1 := float64(time.Nanoseconds()-t0) / 1e9
	t.Log("\nwrite t", int(t1))

	if err = db.accessor.Sync(); err != nil {
		t.Fatal(45, err)
	}
	t.Log("Sync()")
}

func dts(ns int64) string {
	s := ns / 1e9
	sgn := "+"
	if s < 0 {
		sgn = "-"
		s = -s
	}
	return fmt.Sprintf("%s%02d:%02d:%02d", sgn, s/3600, (s/60)%60, s%60)
}
