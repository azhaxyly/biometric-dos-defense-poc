package middleware

import (
	"biometric-dos-defense/internal/pow"
	"biometric-dos-defense/internal/server"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"strings"

	"golang.org/x/time/rate"
)

// DefenseConfig holds configuration for the defense middleware
type DefenseConfig struct {
	RateLimit  rate.Limit
	Burst      int
	Difficulty int
}

// DefenseMiddleware wraps the handler with rate limiting and PoW
func DefenseMiddleware(next http.HandlerFunc, config DefenseConfig) http.HandlerFunc {
	// IP-based rate limiter
	// In a real distributed system, use Redis/Memcached
	limiters := make(map[string]*rate.Limiter)
	var mu sync.Mutex

	getLimiter := func(ip string) *rate.Limiter {
		mu.Lock()
		defer mu.Unlock()

		limiter, exists := limiters[ip]
		if !exists {
			limiter = rate.NewLimiter(config.RateLimit, config.Burst)
			limiters[ip] = limiter
		}
		return limiter
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}

		limiter := getLimiter(ip)

		// Check if request is allowed by rate limiter
		if limiter.Allow() {
			// Pass through
			next(w, r)
			return
		}

		// Rate limit exceeded -> Challenge with PoW
		// Check if the client provided a solution
		solution := r.Header.Get("X-PoW-Solution") // Format: "prefix:nonce"
		
		if solution != "" {
			// Verify solution
			// We need to know the prefix we gave them. 
			// Stateless verification: The client sends "prefix:nonce". 
			// We verify SHA256(prefix+nonce) meets difficulty.
			// To prevent replay of old prefixes, we could sign the prefix or include a timestamp.
			// For this PoC, we'll just verify the work done on *any* prefix they claim.
			// A smarter attacker could pre-compute, so ideally prefix includes time/server-secret.
			// Let's assume the client sends "prefix:nonce"
			
			parts := splitSolution(solution)
			if len(parts) == 2 {
				prefix := parts[0]
				nonce := parts[1]
				
				if pow.VerifySolution(prefix, nonce, config.Difficulty) {
					// Valid PoW, allow request
					// Note: We are bypassing the rate limiter here to allow the "good" user through
					// even if they are technically above the "cheap" rate limit.
					// But we should still probably have a higher "hard" limit.
					next(w, r)
					return
				}
			}
		}

		// Reject and send challenge
		atomic.AddUint64(&server.GlobalMetrics.RequestsDropped, 1)
		
		puzzle, _ := pow.GeneratePuzzle(config.Difficulty)
		
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-PoW-Challenge", puzzle.Prefix)
		w.Header().Set("X-PoW-Difficulty", string(rune(puzzle.Difficulty))) // Simplified
		w.WriteHeader(http.StatusPreconditionRequired) // 428
		
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":      "Rate limit exceeded. Solve PoW.",
			"puzzle":     puzzle,
			"difficulty": config.Difficulty,
		})
	}
}

func splitSolution(s string) []string {
	// Simple helper to split "prefix:nonce"
	return strings.SplitN(s, ":", 2)
}
