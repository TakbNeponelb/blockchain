package consensus

import (
	"blockchain/pkg/shared"
	"strings"
	"time"
)

// Interface defines consensus engine operations
type Interface interface {
	MineBlock(block *shared.Block) *shared.Block
	ValidateBlock(block *shared.Block) bool
	GetDifficulty() int
	SetDifficulty(difficulty int)
}

// ProofOfWork implements the Proof of Work consensus algorithm
type ProofOfWork struct {
	difficulty int
}

// NewPoW creates a new Proof of Work consensus engine
func NewPoW(difficulty int) Interface {
	return &ProofOfWork{
		difficulty: difficulty,
	}
}

// MineBlock mines a block using Proof of Work
func (pow *ProofOfWork) MineBlock(block *shared.Block) *shared.Block {
	target := strings.Repeat("0", pow.difficulty)

	block.Difficulty = pow.difficulty
	block.Nonce = 0

	startTime := time.Now()

	for {
		block.Hash = block.CalculateHash()

		if strings.HasPrefix(block.Hash, target) {
			miningTime := time.Since(startTime)
			block.Data = block.Data + " (Mined in " + miningTime.String() + ")"
			break
		}

		block.Nonce++
	}

	return block
}

// ValidateBlock validates a block's proof of work
func (pow *ProofOfWork) ValidateBlock(block *shared.Block) bool {
	target := strings.Repeat("0", pow.difficulty)

	// Check if hash has required number of leading zeros
	if !strings.HasPrefix(block.Hash, target) {
		return false
	}

	// Verify hash is correct
	return block.IsValid()
}

// GetDifficulty returns current difficulty
func (pow *ProofOfWork) GetDifficulty() int {
	return pow.difficulty
}

// SetDifficulty sets mining difficulty
func (pow *ProofOfWork) SetDifficulty(difficulty int) {
	if difficulty > 0 && difficulty <= 10 {
		pow.difficulty = difficulty
	}
}
