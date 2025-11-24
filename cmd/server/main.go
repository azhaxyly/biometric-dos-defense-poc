package main

import (
	"biometric-dos-defense/internal/middleware"
	"biometric-dos-defense/internal/pow"
	"biometric-dos-defense/internal/server"
	"log"
	"net/http"

	"golang.org/x/time/rate"
)

func main() {
	mux := http.NewServeMux()

	// Configure Defense Middleware
	defenseConfig := middleware.DefenseConfig{
		RateLimit:  rate.Limit(1), // Allow 1 request per second
		Burst:      5,             // Burst of 5
		Difficulty: pow.DefaultDifficulty,
	}

	// Vulnerable endpoint wrapped with defense
	mux.HandleFunc("/auth/webauthn/begin", middleware.DefenseMiddleware(server.WebAuthnBeginHandler, defenseConfig))

	// Metrics endpoint (unprotected for visibility)
	mux.HandleFunc("/metrics", server.MetricsHandler)

	log.Println("Starting protected server on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
