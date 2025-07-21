package shared

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Block represents a block in the blockchain
type Block struct {
	ID           string        `json:"id" db:"id"`
	Index        int64         `json:"index" db:"index"`
	Timestamp    time.Time     `json:"timestamp" db:"timestamp"`
	PreviousHash string        `json:"previous_hash" db:"previous_hash"`
	Hash         string        `json:"hash" db:"hash"`
	Data         string        `json:"data" db:"data"`
	Nonce        int64         `json:"nonce" db:"nonce"`
	Difficulty   int           `json:"difficulty" db:"difficulty"`
	Transactions []Transaction `json:"transactions"`
}

// Transaction represents a transaction in the blockchain
type Transaction struct {
	ID        string    `json:"id" db:"id"`
	From      string    `json:"from" db:"from_address"`
	To        string    `json:"to" db:"to_address"`
	Amount    float64   `json:"amount" db:"amount"`
	Fee       float64   `json:"fee" db:"fee"`
	Data      string    `json:"data" db:"data"`
	Timestamp time.Time `json:"timestamp" db:"timestamp"`
	Signature string    `json:"signature" db:"signature"`
	BlockHash string    `json:"block_hash" db:"block_hash"`
}

// User represents a system user
type User struct {
	ID       string    `json:"id" db:"id"`
	Username string    `json:"username" db:"username"`
	Email    string    `json:"email" db:"email"`
	Password string    `json:"-" db:"password_hash"`
	Address  string    `json:"address" db:"wallet_address"`
	Balance  float64   `json:"balance" db:"balance"`
	Created  time.Time `json:"created" db:"created_at"`
}

// Peer represents a P2P network peer
type Peer struct {
	ID       string    `json:"id"`
	Address  string    `json:"address"`
	Port     int       `json:"port"`
	Online   bool      `json:"online"`
	LastSeen time.Time `json:"last_seen"`
}

// NetworkMessage represents a message in the P2P network
type NetworkMessage struct {
	Type      string      `json:"type"`
	From      string      `json:"from"`
	To        string      `json:"to"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// RegisterRequest represents a registration request
type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

// CreateTransactionRequest represents a transaction creation request
type CreateTransactionRequest struct {
	To     string  `json:"to" binding:"required"`
	Amount float64 `json:"amount" binding:"required,gt=0"`
	Fee    float64 `json:"fee" binding:"required,gte=0"`
	Data   string  `json:"data"`
}

// AuthResponse represents authentication response
type AuthResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

// APIResponse represents a generic API response
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// BlockchainStats represents blockchain statistics
type BlockchainStats struct {
	BlockCount       int64   `json:"block_count"`
	TransactionCount int64   `json:"transaction_count"`
	TotalValue       float64 `json:"total_value"`
	LastBlockHash    string  `json:"last_block_hash"`
	Difficulty       int     `json:"difficulty"`
	PeerCount        int     `json:"peer_count"`
}

// CalculateHash calculates the hash of a block
func (b *Block) CalculateHash() string {
	blockString := fmt.Sprintf("%d%s%s%s%d%d",
		b.Index, b.Timestamp.Format(time.RFC3339), b.PreviousHash, b.Data, b.Nonce, b.Difficulty)

	hash := sha256.Sum256([]byte(blockString))
	return hex.EncodeToString(hash[:])
}

// IsValid checks if a block is valid
func (b *Block) IsValid() bool {
	return b.Hash == b.CalculateHash()
}

// ToJSON converts block to JSON string
func (b *Block) ToJSON() (string, error) {
	data, err := json.Marshal(b)
	return string(data), err
}

// FromJSON creates block from JSON string
func (b *Block) FromJSON(jsonStr string) error {
	return json.Unmarshal([]byte(jsonStr), b)
}

// CalculateTransactionHash calculates hash for a transaction
func (t *Transaction) CalculateHash() string {
	txString := fmt.Sprintf("%s%s%.8f%.8f%s%s",
		t.From, t.To, t.Amount, t.Fee, t.Data, t.Timestamp.Format(time.RFC3339))

	hash := sha256.Sum256([]byte(txString))
	return hex.EncodeToString(hash[:])
}

// Constants for message types
const (
	MessageTypeBlock       = "block"
	MessageTypeTransaction = "transaction"
	MessageTypePeerList    = "peer_list"
	MessageTypeHandshake   = "handshake"
	MessageTypeSync        = "sync"
	MessageTypePing        = "ping"
	MessageTypePong        = "pong"
)

// Network message constructors
func NewBlockMessage(from string, block *Block) NetworkMessage {
	return NetworkMessage{
		Type:      MessageTypeBlock,
		From:      from,
		Data:      block,
		Timestamp: time.Now(),
	}
}

func NewTransactionMessage(from string, tx *Transaction) NetworkMessage {
	return NetworkMessage{
		Type:      MessageTypeTransaction,
		From:      from,
		Data:      tx,
		Timestamp: time.Now(),
	}
}

func NewHandshakeMessage(from string, peers []Peer) NetworkMessage {
	return NetworkMessage{
		Type:      MessageTypeHandshake,
		From:      from,
		Data:      peers,
		Timestamp: time.Now(),
	}
}
