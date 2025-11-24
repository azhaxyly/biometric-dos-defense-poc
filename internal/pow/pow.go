package pow

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
)

// Difficulty is the number of leading zero bits required in the hash
const DefaultDifficulty = 20 // Adjust based on desired cost

// Puzzle represents the challenge sent to the client
type Puzzle struct {
	Prefix     string `json:"prefix"`
	Difficulty int    `json:"difficulty"`
}

// GeneratePuzzle creates a new random prefix for the client to solve
func GeneratePuzzle(difficulty int) (Puzzle, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return Puzzle{}, err
	}
	return Puzzle{
		Prefix:     hex.EncodeToString(bytes),
		Difficulty: difficulty,
	}, nil
}

// VerifySolution checks if SHA256(prefix + nonce) has enough leading zeros
func VerifySolution(prefix string, nonce string, difficulty int) bool {
	data := prefix + nonce
	hash := sha256.Sum256([]byte(data))

	// Convert hash to big int to check leading zeros
	// A simpler way for fixed difficulty is checking leading hex chars,
	// but bit-level is more precise.
	// For this PoC, we'll check if the hash (as a big int) is less than 2^(256-difficulty)
	
	hashInt := new(big.Int).SetBytes(hash[:])
	target := new(big.Int).Lsh(big.NewInt(1), uint(256-difficulty))
	
	// If hashInt < target, it means it has enough leading zeros
	// Wait, target is 1 << (256 - diff). 
	// Max hash is 2^256 - 1.
	// We want the top 'diff' bits to be zero.
	// So the number must be less than 2^(256-diff).
	
	return hashInt.Cmp(target) == -1
}
