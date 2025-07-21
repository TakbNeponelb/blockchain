package blockchain

import (
	"blockchain/internal/consensus"
	"blockchain/internal/crypto"
	"blockchain/internal/datastore"
	"blockchain/pkg/shared"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Blockchain represents the blockchain structure
type Blockchain struct {
	dataStore       datastore.Interface
	cryptoService   crypto.Interface
	consensusEngine consensus.Interface
	pendingTxs      []shared.Transaction
	mutex           sync.RWMutex
	difficulty      int
	miningReward    float64
	transactionPool map[string]shared.Transaction
	isValidating    bool
	validationMutex sync.Mutex
}

// Interface defines blockchain operations
type Interface interface {
	Initialize() error
	AddBlock(data string) (*shared.Block, error)
	GetLatestBlock() (*shared.Block, error)
	GetBlockByHash(hash string) (*shared.Block, error)
	GetBlockByIndex(index int64) (*shared.Block, error)
	GetBlocks(limit, offset int) ([]shared.Block, error)
	AddTransaction(tx shared.Transaction) error
	GetTransaction(id string) (*shared.Transaction, error)
	GetTransactionsByAddress(address string) ([]shared.Transaction, error)
	GetPendingTransactions() []shared.Transaction
	MineBlock(minerAddress string) (*shared.Block, error)
	ValidateChain() error
	GetBalance(address string) (float64, error)
	GetStats() (*shared.BlockchainStats, error)
	SyncWithPeer(blocks []shared.Block) error
}

// New creates a new blockchain instance
func New(dataStore datastore.Interface, cryptoService crypto.Interface, consensusEngine consensus.Interface) Interface {
	return &Blockchain{
		dataStore:       dataStore,
		cryptoService:   cryptoService,
		consensusEngine: consensusEngine,
		pendingTxs:      make([]shared.Transaction, 0),
		difficulty:      4,
		miningReward:    10.0,
		transactionPool: make(map[string]shared.Transaction),
	}
}

// Initialize initializes the blockchain with genesis block if needed
func (bc *Blockchain) Initialize() error {
	// Check if genesis block exists
	blocks, err := bc.dataStore.GetBlocks(1, 0)
	if err != nil {
		return fmt.Errorf("failed to check for genesis block: %w", err)
	}

	if len(blocks) == 0 {
		// Create genesis block
		genesisBlock := shared.Block{
			ID:           uuid.New().String(),
			Index:        0,
			Timestamp:    time.Now(),
			PreviousHash: "0",
			Data:         "Genesis Block",
			Nonce:        0,
			Difficulty:   bc.difficulty,
		}

		// Mine genesis block
		minedBlock := bc.consensusEngine.MineBlock(&genesisBlock)

		// Save genesis block
		if err := bc.dataStore.SaveBlock(minedBlock); err != nil {
			return fmt.Errorf("failed to save genesis block: %w", err)
		}

		log.Println("Genesis block created and saved")
	}

	return nil
}

// AddBlock adds a new block to the blockchain
func (bc *Blockchain) AddBlock(data string) (*shared.Block, error) {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	latestBlock, err := bc.GetLatestBlock()
	if err != nil {
		return nil, fmt.Errorf("failed to get latest block: %w", err)
	}

	newBlock := shared.Block{
		ID:           uuid.New().String(),
		Index:        latestBlock.Index + 1,
		Timestamp:    time.Now(),
		PreviousHash: latestBlock.Hash,
		Data:         data,
		Difficulty:   bc.difficulty,
		Transactions: bc.pendingTxs,
	}

	// Mine the block
	minedBlock := bc.consensusEngine.MineBlock(&newBlock)

	// Validate the block
	if err := bc.validateNewBlock(minedBlock, latestBlock); err != nil {
		return nil, fmt.Errorf("block validation failed: %w", err)
	}

	// Save the block
	if err := bc.dataStore.SaveBlock(minedBlock); err != nil {
		return nil, fmt.Errorf("failed to save block: %w", err)
	}

	// Save transactions
	for _, tx := range bc.pendingTxs {
		tx.BlockHash = minedBlock.Hash
		if err := bc.dataStore.SaveTransaction(&tx); err != nil {
			log.Printf("Failed to save transaction %s: %v", tx.ID, err)
		}
	}

	// Clear pending transactions
	bc.pendingTxs = make([]shared.Transaction, 0)

	return minedBlock, nil
}

// GetLatestBlock returns the latest block in the blockchain
func (bc *Blockchain) GetLatestBlock() (*shared.Block, error) {
	blocks, err := bc.dataStore.GetBlocks(1, 0)
	if err != nil {
		return nil, err
	}

	if len(blocks) == 0 {
		return nil, errors.New("no blocks found")
	}

	return &blocks[0], nil
}

// GetBlockByHash returns a block by its hash
func (bc *Blockchain) GetBlockByHash(hash string) (*shared.Block, error) {
	return bc.dataStore.GetBlockByHash(hash)
}

// GetBlockByIndex returns a block by its index
func (bc *Blockchain) GetBlockByIndex(index int64) (*shared.Block, error) {
	return bc.dataStore.GetBlockByIndex(index)
}

// GetBlocks returns a list of blocks with pagination
func (bc *Blockchain) GetBlocks(limit, offset int) ([]shared.Block, error) {
	return bc.dataStore.GetBlocks(limit, offset)
}

// AddTransaction adds a transaction to the pending pool
func (bc *Blockchain) AddTransaction(tx shared.Transaction) error {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	// Validate transaction
	if err := bc.validateTransaction(&tx); err != nil {
		return fmt.Errorf("transaction validation failed: %w", err)
	}

	// Generate transaction ID if not provided
	if tx.ID == "" {
		tx.ID = uuid.New().String()
	}

	// Set timestamp if not provided
	if tx.Timestamp.IsZero() {
		tx.Timestamp = time.Now()
	}

	// Add to pending transactions
	bc.pendingTxs = append(bc.pendingTxs, tx)
	bc.transactionPool[tx.ID] = tx

	return nil
}

// GetTransaction returns a transaction by ID
func (bc *Blockchain) GetTransaction(id string) (*shared.Transaction, error) {
	return bc.dataStore.GetTransaction(id)
}

// GetTransactionsByAddress returns transactions for a given address
func (bc *Blockchain) GetTransactionsByAddress(address string) ([]shared.Transaction, error) {
	return bc.dataStore.GetTransactionsByAddress(address)
}

// GetPendingTransactions returns all pending transactions
func (bc *Blockchain) GetPendingTransactions() []shared.Transaction {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()

	return append([]shared.Transaction{}, bc.pendingTxs...)
}

// MineBlock mines a new block with pending transactions
func (bc *Blockchain) MineBlock(minerAddress string) (*shared.Block, error) {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	if len(bc.pendingTxs) == 0 {
		return nil, errors.New("no pending transactions to mine")
	}

	// Add mining reward transaction
	rewardTx := shared.Transaction{
		ID:        uuid.New().String(),
		From:      "system",
		To:        minerAddress,
		Amount:    bc.miningReward,
		Fee:       0,
		Data:      "Mining reward",
		Timestamp: time.Now(),
	}

	bc.pendingTxs = append(bc.pendingTxs, rewardTx)

	// Create block with pending transactions
	latestBlock, err := bc.GetLatestBlock()
	if err != nil {
		return nil, err
	}

	newBlock := shared.Block{
		ID:           uuid.New().String(),
		Index:        latestBlock.Index + 1,
		Timestamp:    time.Now(),
		PreviousHash: latestBlock.Hash,
		Data:         fmt.Sprintf("Block with %d transactions", len(bc.pendingTxs)),
		Difficulty:   bc.difficulty,
		Transactions: bc.pendingTxs,
	}

	// Mine the block
	minedBlock := bc.consensusEngine.MineBlock(&newBlock)

	// Save the block
	if err := bc.dataStore.SaveBlock(minedBlock); err != nil {
		return nil, err
	}

	// Save transactions
	for _, tx := range bc.pendingTxs {
		tx.BlockHash = minedBlock.Hash
		if err := bc.dataStore.SaveTransaction(&tx); err != nil {
			log.Printf("Failed to save transaction %s: %v", tx.ID, err)
		}
	}

	// Clear pending transactions
	bc.pendingTxs = make([]shared.Transaction, 0)

	return minedBlock, nil
}

// ValidateChain validates the entire blockchain
func (bc *Blockchain) ValidateChain() error {
	bc.validationMutex.Lock()
	defer bc.validationMutex.Unlock()

	if bc.isValidating {
		return errors.New("validation already in progress")
	}

	bc.isValidating = true
	defer func() { bc.isValidating = false }()

	blocks, err := bc.dataStore.GetAllBlocks()
	if err != nil {
		return fmt.Errorf("failed to get blocks for validation: %w", err)
	}

	if len(blocks) == 0 {
		return errors.New("no blocks to validate")
	}

	// Validate genesis block
	if blocks[0].Index != 0 || blocks[0].PreviousHash != "0" {
		return errors.New("invalid genesis block")
	}

	// Validate chain
	for i := 1; i < len(blocks); i++ {
		currentBlock := &blocks[i]
		previousBlock := &blocks[i-1]

		if err := bc.validateNewBlock(currentBlock, previousBlock); err != nil {
			return fmt.Errorf("block %d validation failed: %w", currentBlock.Index, err)
		}
	}

	return nil
}

// GetBalance returns the balance for a given address
func (bc *Blockchain) GetBalance(address string) (float64, error) {
	transactions, err := bc.GetTransactionsByAddress(address)
	if err != nil {
		return 0, err
	}

	balance := 0.0
	for _, tx := range transactions {
		if tx.To == address {
			balance += tx.Amount
		}
		if tx.From == address {
			balance -= (tx.Amount + tx.Fee)
		}
	}

	return balance, nil
}

// GetStats returns blockchain statistics
func (bc *Blockchain) GetStats() (*shared.BlockchainStats, error) {
	blockCount, err := bc.dataStore.GetBlockCount()
	if err != nil {
		return nil, err
	}

	txCount, err := bc.dataStore.GetTransactionCount()
	if err != nil {
		return nil, err
	}

	latestBlock, err := bc.GetLatestBlock()
	if err != nil {
		return nil, err
	}

	return &shared.BlockchainStats{
		BlockCount:       blockCount,
		TransactionCount: txCount,
		LastBlockHash:    latestBlock.Hash,
		Difficulty:       bc.difficulty,
		PeerCount:        0, // This will be updated by P2P module
	}, nil
}

// SyncWithPeer synchronizes blockchain with peer data
func (bc *Blockchain) SyncWithPeer(blocks []shared.Block) error {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	if len(blocks) == 0 {
		return nil
	}

	// Validate incoming blocks
	for i := 1; i < len(blocks); i++ {
		if err := bc.validateNewBlock(&blocks[i], &blocks[i-1]); err != nil {
			return fmt.Errorf("sync validation failed at block %d: %w", blocks[i].Index, err)
		}
	}

	// Get current latest block
	currentLatest, err := bc.GetLatestBlock()
	if err != nil {
		return err
	}

	// Only sync if peer chain is longer
	if blocks[len(blocks)-1].Index > currentLatest.Index {
		// Save new blocks
		for _, block := range blocks {
			if block.Index > currentLatest.Index {
				if err := bc.dataStore.SaveBlock(&block); err != nil {
					return fmt.Errorf("failed to save synced block: %w", err)
				}
			}
		}
	}

	return nil
}

// validateNewBlock validates a new block against the previous block
func (bc *Blockchain) validateNewBlock(newBlock, previousBlock *shared.Block) error {
	// Check index
	if newBlock.Index != previousBlock.Index+1 {
		return errors.New("invalid block index")
	}

	// Check previous hash
	if newBlock.PreviousHash != previousBlock.Hash {
		return errors.New("invalid previous hash")
	}

	// Check hash
	if !newBlock.IsValid() {
		return errors.New("invalid block hash")
	}

	// Validate proof of work
	if !bc.consensusEngine.ValidateBlock(newBlock) {
		return errors.New("invalid proof of work")
	}

	// Check timestamp
	if newBlock.Timestamp.Before(previousBlock.Timestamp) {
		return errors.New("invalid timestamp")
	}

	return nil
}

// validateTransaction validates a transaction
func (bc *Blockchain) validateTransaction(tx *shared.Transaction) error {
	// Check required fields
	if tx.From == "" || tx.To == "" {
		return errors.New("from and to addresses are required")
	}

	if tx.Amount <= 0 {
		return errors.New("amount must be positive")
	}

	if tx.Fee < 0 {
		return errors.New("fee cannot be negative")
	}

	// Check if sender has sufficient balance (skip for system transactions)
	if tx.From != "system" {
		balance, err := bc.GetBalance(tx.From)
		if err != nil {
			return fmt.Errorf("failed to get sender balance: %w", err)
		}

		if balance < tx.Amount+tx.Fee {
			return errors.New("insufficient balance")
		}
	}

	return nil
}
