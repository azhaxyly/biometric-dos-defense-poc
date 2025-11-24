package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var (
	targetURL   = "http://localhost:8080/auth/webauthn/begin"
	concurrency = flag.Int("c", 10, "Number of concurrent attackers")
	mode        = flag.String("mode", "dumb", "Mode: 'dumb' (ignore PoW) or 'smart' (solve PoW)")
	duration    = flag.Duration("d", 10*time.Second, "Duration of attack")
)

type Stats struct {
	RequestsSent    uint64
	Success         uint64
	RateLimited     uint64 // 429 or 428
	PoWSolved       uint64
	Failures        uint64
}

var stats Stats

func main() {
	flag.Parse()

	log.Printf("Starting attacker in %s mode with %d workers for %v", *mode, *concurrency, *duration)

	var wg sync.WaitGroup
	start := time.Now()
	done := make(chan struct{})

	// Timer to stop attack
	go func() {
		time.Sleep(*duration)
		close(done)
	}()

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					attack()
				}
			}
		}()
	}

	wg.Wait()
	elapsed := time.Since(start)

	log.Println("Attack finished.")
	log.Printf("Duration: %v", elapsed)
	log.Printf("Requests Sent: %d", stats.RequestsSent)
	log.Printf("Success (200 OK): %d", stats.Success)
	log.Printf("Rate Limited/Challenge (429/428): %d", stats.RateLimited)
	log.Printf("PoW Solved: %d", stats.PoWSolved)
	log.Printf("Failures: %d", stats.Failures)
}

func attack() {
	atomic.AddUint64(&stats.RequestsSent, 1)

	req, _ := http.NewRequest("POST", targetURL, nil)
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		atomic.AddUint64(&stats.Failures, 1)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		atomic.AddUint64(&stats.Success, 1)
		return
	}

	if resp.StatusCode == http.StatusPreconditionRequired { // 428
		atomic.AddUint64(&stats.RateLimited, 1)

		if *mode == "smart" {
			// Solve PoW
			solvePoW(resp)
		}
		return
	}

	// Other errors
	atomic.AddUint64(&stats.Failures, 1)
}

func solvePoW(resp *http.Response) {
	// Parse challenge
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return
	}

	puzzleMap, ok := body["puzzle"].(map[string]interface{})
	if !ok {
		return
	}
	prefix := puzzleMap["prefix"].(string)
	difficulty := int(body["difficulty"].(float64))

	// Solve it
	nonce := findNonce(prefix, difficulty)
	
	// Retry with solution
	atomic.AddUint64(&stats.PoWSolved, 1)
	
	req, _ := http.NewRequest("POST", targetURL, nil)
	req.Header.Set("X-PoW-Solution", prefix+":"+nonce)
	
	client := &http.Client{Timeout: 5 * time.Second}
	resp2, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp2.Body.Close()
	
	if resp2.StatusCode == http.StatusOK {
		atomic.AddUint64(&stats.Success, 1)
	}
}

func findNonce(prefix string, difficulty int) string {
	// Brute force nonce
	// This is CPU intensive for the attacker!
	target := new(big.Int).Lsh(big.NewInt(1), uint(256-difficulty))
	
	var nonce int64
	for {
		nonceStr := strconv.FormatInt(nonce, 16)
		data := prefix + nonceStr
		hash := sha256.Sum256([]byte(data))
		
		hashInt := new(big.Int).SetBytes(hash[:])
		if hashInt.Cmp(target) == -1 {
			return nonceStr
		}
		nonce++
	}
}
