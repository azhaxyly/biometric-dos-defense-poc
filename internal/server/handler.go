package server

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"
)

// Metrics holds the server statistics
type Metrics struct {
	RequestsProcessed uint64
	RequestsDropped   uint64
}

var GlobalMetrics Metrics

// HeavyWorkload simulates a CPU-intensive task (e.g., cryptographic operations for WebAuthn)
func HeavyWorkload() {
	// Simulate CPU load by hashing a string multiple times
	// In a real WebAuthn scenario, this would be parsing certs, verifying signatures, etc.
	start := time.Now()
	data := []byte("simulate_heavy_load_for_webauthn_handshake")
	for i := 0; i < 100000; i++ {
		h := sha256.Sum256(data)
		data = h[:]
	}
	// Ensure it takes at least some noticeable time, but the loop above is the CPU burner.
	// We can also add a small sleep to simulate I/O or other latencies if needed,
	// but for DoS simulation, CPU burn is key.
	_ = start
}

// WebAuthnBeginHandler is the vulnerable endpoint
func WebAuthnBeginHandler(w http.ResponseWriter, r *http.Request) {
	// Log the request (optional, can be noisy under flood)
	// log.Printf("Received request from %s", r.RemoteAddr)

	// Simulate the heavy workload
	HeavyWorkload()

	// Increment processed counter
	atomic.AddUint64(&GlobalMetrics.RequestsProcessed, 1)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "WebAuthn challenge generated",
	})
}

// MetricsHandler exposes the current metrics
func MetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]uint64{
		"processed": atomic.LoadUint64(&GlobalMetrics.RequestsProcessed),
		"dropped":   atomic.LoadUint64(&GlobalMetrics.RequestsDropped),
	})
}
