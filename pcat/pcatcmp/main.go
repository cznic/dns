// Copyright (c) 2011 CZ.NIC z.s.p.o. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// blame: jnml, labs.nic.cz

package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/cznic/dns/pcat"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"regexp"
	"runtime"
	"sort"
)

func init() {
	runtime.GOMAXPROCS(3)
}

func load(db *pcat.DB, fn string, f io.ByteReader, part int, done chan error, idx chan int) {
	defer func() {
		e := recover()
		switch x := e.(type) {
		case nil:
			done <- nil
		case error:
			done <- x
		default:
			log.Fatalf("%T: internal error", e)
		}
	}()

	if err := pcat.Scan(fn, f, func(r *pcat.Record) bool {
		idx <- r.Id
		if err := db.RSet(uint32(part), r); err != nil {
			panic(err)
		}

		return true
	}); err != nil {
		panic(err)
	}
}

func load2(j *job) {
	done := make(chan error, 3)
	idx := make(chan int, 1000)

	go func() {
		for recn := range idx {
			j.index = append(j.index, recn)
		}
		done <- nil
	}()
	go load(j.db, j.fna, j.fa, 1, done, idx)
	go load(j.db, j.fnb, j.fb, 2, done, idx)

	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			log.Fatal(err)
		}
	}
	close(idx)
	<-done

	sort.Ints(j.index)
	var w, last int
	for _, id := range j.index {
		if last != id || w == 0 {
			j.index[w] = id
			w++
		}
		last = id
	}
	j.index = append([]int{}, j.index[:w]...)
}

func getReader(fn string) io.ByteReader {
	f, err := os.Open(fn)
	if err != nil {
		log.Fatal(err)
	}

	return bufio.NewReader(f)
}

func setup(j *job, cont func(*job)) {
	dir, err := ioutil.TempDir("", path.Base(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		os.RemoveAll(dir)
	}()

	j.db, err = pcat.NewDB(dir + "/db")
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		j.db.Close()
	}()

	load2(j)
	if cont != nil {
		cont(j)
	}
}

type job struct {
	fa, fb      io.ByteReader
	fna, fnb    string
	db          *pcat.DB
	index       []int
	optFrom     *int
	optMax      *int
	optRE       *string
	optReadable *bool
	optSOC      *bool
	optVerbose  *bool
	optWire     *bool
	re          *regexp.Regexp
	total       int // pcat records processed
	totalRDiffs int // detected reply diffs
	totals      map[string]int
}

func (j *job) err(id, n int, typ, format string, v ...interface{}) {
	s := fmt.Sprintf(format, v...)
	if j.re != nil && !j.re.MatchString(s) {
		return
	}

	j.totals[typ] += n
	fmt.Printf("!%s:%d: %s\n", typ, id, s)
}

func (j *job) summary() {
	totals := []string{}
	for typ, v := range j.totals {
		totals = append(totals, fmt.Sprintf("!total_%s: %6d/%d %5.2f%%",
			typ, v, j.total, 100*float64(v)/float64(j.total)))
	}
	sort.Strings(totals)
	for _, v := range totals {
		fmt.Println(v)
	}
	fmt.Printf(
		"# Grand totals ================================================================\n"+
			"Replies:           %6d         # Only valid (non malformed) messages counted\n"+
			"Different_replies: %6d %6.2f%% # Compression diffs/missing pcat recs NOT counted\n",
		j.total, j.totalRDiffs, 100*float64(j.totalRDiffs)/float64(j.total),
	)
}

func main() {
	j := &job{totals: map[string]int{}}

	j.optFrom = flag.Int("from", -1, "consider record IDs >= from")
	j.optMax = flag.Int("n", -1, "consider max N records, -1 == all")
	j.optRE = flag.String("re", "", "error results regexp filter")
	j.optReadable = flag.Bool("dr", false, "dump as readable text")
	j.optSOC = flag.Bool("soc", false, "detect suboptimal compression (first occurrence only)")
	j.optVerbose = flag.Bool("v", false, "verbose")
	j.optWire = flag.Bool("dh", false, "dump as hex")

	flag.Parse()

	switch flag.NArg() {
	case 1:
		j.fna, j.fnb = flag.Arg(0), os.Stdin.Name()
		j.fa, j.fb = getReader(j.fna), bufio.NewReader(os.Stdin)
	case 2:
		j.fna, j.fnb = flag.Arg(0), flag.Arg(1)
		j.fa, j.fb = getReader(j.fna), getReader(j.fnb)
	default:
		log.Fatal("expected 1 or 2 arguments")
	}

	if *j.optRE != "" {
		var err error
		if j.re, err = regexp.Compile(*j.optRE); err != nil {
			log.Fatal(err)
		}
	}

	setup(j, do)
	switch len(j.totals) {
	case 0:
		os.Exit(0)
	default:
		os.Exit(1)
	}
}
