package datastore

import (
	"blockchain/pkg/shared"
	"database/sql"
	"encoding/json"
	"fmt"
)

// Interface defines datastore operations
type Interface interface {
	InitTables() error
	SaveBlock(block *shared.Block) error
	GetBlockByHash(hash string) (*shared.Block, error)
	GetBlockByIndex(index int64) (*shared.Block, error)
	GetBlocks(limit, offset int) ([]shared.Block, error)
	GetAllBlocks() ([]shared.Block, error)
	GetBlockCount() (int64, error)
	SaveTransaction(tx *shared.Transaction) error
	GetTransaction(id string) (*shared.Transaction, error)
	GetTransactionsByAddress(address string) ([]shared.Transaction, error)
	GetTransactionCount() (int64, error)
	SaveUser(user *shared.User) error
	GetUserByUsername(username string) (*shared.User, error)
	GetUserByID(id string) (*shared.User, error)
	UpdateUserBalance(userID string, balance float64) error
}

// PostgresStore implements the datastore interface using PostgreSQL
type PostgresStore struct {
	db *sql.DB
}

// New creates a new PostgreSQL datastore
func New(db *sql.DB) Interface {
	return &PostgresStore{db: db}
}

// InitTables creates necessary database tables
func (ps *PostgresStore) InitTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS blocks (
			id VARCHAR(255) PRIMARY KEY,
			index BIGINT UNIQUE NOT NULL,
			timestamp TIMESTAMP NOT NULL,
			previous_hash VARCHAR(255) NOT NULL,
			hash VARCHAR(255) UNIQUE NOT NULL,
			data TEXT NOT NULL,
			nonce BIGINT NOT NULL,
			difficulty INTEGER NOT NULL,
			transactions JSONB,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		`CREATE TABLE IF NOT EXISTS transactions (
			id VARCHAR(255) PRIMARY KEY,
			from_address VARCHAR(255) NOT NULL,
			to_address VARCHAR(255) NOT NULL,
			amount DECIMAL(18,8) NOT NULL,
			fee DECIMAL(18,8) NOT NULL DEFAULT 0,
			data TEXT,
			timestamp TIMESTAMP NOT NULL,
			signature VARCHAR(255),
			block_hash VARCHAR(255) REFERENCES blocks(hash),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		`CREATE TABLE IF NOT EXISTS users (
			id VARCHAR(255) PRIMARY KEY,
			username VARCHAR(50) UNIQUE NOT NULL,
			email VARCHAR(100) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			wallet_address VARCHAR(255) UNIQUE NOT NULL,
			balance DECIMAL(18,8) DEFAULT 0,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		`CREATE INDEX IF NOT EXISTS idx_blocks_index ON blocks(index)`,
		`CREATE INDEX IF NOT EXISTS idx_blocks_hash ON blocks(hash)`,
		`CREATE INDEX IF NOT EXISTS idx_transactions_from ON transactions(from_address)`,
		`CREATE INDEX IF NOT EXISTS idx_transactions_to ON transactions(to_address)`,
		`CREATE INDEX IF NOT EXISTS idx_transactions_block ON transactions(block_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`,
		`CREATE INDEX IF NOT EXISTS idx_users_address ON users(wallet_address)`,
	}

	for _, query := range queries {
		if _, err := ps.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query: %w", err)
		}
	}

	return nil
}

// SaveBlock saves a block to the database
func (ps *PostgresStore) SaveBlock(block *shared.Block) error {
	transactionsJSON, err := json.Marshal(block.Transactions)
	if err != nil {
		return fmt.Errorf("failed to marshal transactions: %w", err)
	}

	query := `
		INSERT INTO blocks (id, index, timestamp, previous_hash, hash, data, nonce, difficulty, transactions)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (id) DO NOTHING`

	_, err = ps.db.Exec(query,
		block.ID, block.Index, block.Timestamp, block.PreviousHash,
		block.Hash, block.Data, block.Nonce, block.Difficulty, transactionsJSON)

	return err
}

// GetBlockByHash retrieves a block by its hash
func (ps *PostgresStore) GetBlockByHash(hash string) (*shared.Block, error) {
	query := `SELECT id, index, timestamp, previous_hash, hash, data, nonce, difficulty, transactions 
			  FROM blocks WHERE hash = $1`

	var block shared.Block
	var transactionsJSON []byte

	err := ps.db.QueryRow(query, hash).Scan(
		&block.ID, &block.Index, &block.Timestamp, &block.PreviousHash,
		&block.Hash, &block.Data, &block.Nonce, &block.Difficulty, &transactionsJSON)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("block not found")
		}
		return nil, err
	}

	if len(transactionsJSON) > 0 {
		if err := json.Unmarshal(transactionsJSON, &block.Transactions); err != nil {
			return nil, fmt.Errorf("failed to unmarshal transactions: %w", err)
		}
	}

	return &block, nil
}

// GetBlockByIndex retrieves a block by its index
func (ps *PostgresStore) GetBlockByIndex(index int64) (*shared.Block, error) {
	query := `SELECT id, index, timestamp, previous_hash, hash, data, nonce, difficulty, transactions 
			  FROM blocks WHERE index = $1`

	var block shared.Block
	var transactionsJSON []byte

	err := ps.db.QueryRow(query, index).Scan(
		&block.ID, &block.Index, &block.Timestamp, &block.PreviousHash,
		&block.Hash, &block.Data, &block.Nonce, &block.Difficulty, &transactionsJSON)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("block not found")
		}
		return nil, err
	}

	if len(transactionsJSON) > 0 {
		if err := json.Unmarshal(transactionsJSON, &block.Transactions); err != nil {
			return nil, fmt.Errorf("failed to unmarshal transactions: %w", err)
		}
	}

	return &block, nil
}

// GetBlocks retrieves blocks with pagination
func (ps *PostgresStore) GetBlocks(limit, offset int) ([]shared.Block, error) {
	query := `SELECT id, index, timestamp, previous_hash, hash, data, nonce, difficulty, transactions 
			  FROM blocks ORDER BY index DESC LIMIT $1 OFFSET $2`

	rows, err := ps.db.Query(query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var blocks []shared.Block
	for rows.Next() {
		var block shared.Block
		var transactionsJSON []byte

		err := rows.Scan(
			&block.ID, &block.Index, &block.Timestamp, &block.PreviousHash,
			&block.Hash, &block.Data, &block.Nonce, &block.Difficulty, &transactionsJSON)

		if err != nil {
			return nil, err
		}

		if len(transactionsJSON) > 0 {
			if err := json.Unmarshal(transactionsJSON, &block.Transactions); err != nil {
				return nil, fmt.Errorf("failed to unmarshal transactions: %w", err)
			}
		}

		blocks = append(blocks, block)
	}

	return blocks, nil
}

// GetAllBlocks retrieves all blocks
func (ps *PostgresStore) GetAllBlocks() ([]shared.Block, error) {
	query := `SELECT id, index, timestamp, previous_hash, hash, data, nonce, difficulty, transactions 
			  FROM blocks ORDER BY index ASC`

	rows, err := ps.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var blocks []shared.Block
	for rows.Next() {
		var block shared.Block
		var transactionsJSON []byte

		err := rows.Scan(
			&block.ID, &block.Index, &block.Timestamp, &block.PreviousHash,
			&block.Hash, &block.Data, &block.Nonce, &block.Difficulty, &transactionsJSON)

		if err != nil {
			return nil, err
		}

		if len(transactionsJSON) > 0 {
			if err := json.Unmarshal(transactionsJSON, &block.Transactions); err != nil {
				return nil, fmt.Errorf("failed to unmarshal transactions: %w", err)
			}
		}

		blocks = append(blocks, block)
	}

	return blocks, nil
}

// GetBlockCount returns the total number of blocks
func (ps *PostgresStore) GetBlockCount() (int64, error) {
	query := `SELECT COUNT(*) FROM blocks`

	var count int64
	err := ps.db.QueryRow(query).Scan(&count)
	return count, err
}

// SaveTransaction saves a transaction to the database
func (ps *PostgresStore) SaveTransaction(tx *shared.Transaction) error {
	query := `
		INSERT INTO transactions (id, from_address, to_address, amount, fee, data, timestamp, signature, block_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (id) DO NOTHING`

	_, err := ps.db.Exec(query,
		tx.ID, tx.From, tx.To, tx.Amount, tx.Fee,
		tx.Data, tx.Timestamp, tx.Signature, tx.BlockHash)

	return err
}

// GetTransaction retrieves a transaction by ID
func (ps *PostgresStore) GetTransaction(id string) (*shared.Transaction, error) {
	query := `SELECT id, from_address, to_address, amount, fee, data, timestamp, signature, block_hash 
			  FROM transactions WHERE id = $1`

	var tx shared.Transaction
	err := ps.db.QueryRow(query, id).Scan(
		&tx.ID, &tx.From, &tx.To, &tx.Amount, &tx.Fee,
		&tx.Data, &tx.Timestamp, &tx.Signature, &tx.BlockHash)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("transaction not found")
		}
		return nil, err
	}

	return &tx, nil
}

// GetTransactionsByAddress retrieves transactions for an address
func (ps *PostgresStore) GetTransactionsByAddress(address string) ([]shared.Transaction, error) {
	query := `SELECT id, from_address, to_address, amount, fee, data, timestamp, signature, block_hash 
			  FROM transactions WHERE from_address = $1 OR to_address = $1 ORDER BY timestamp DESC`

	rows, err := ps.db.Query(query, address)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var transactions []shared.Transaction
	for rows.Next() {
		var tx shared.Transaction
		err := rows.Scan(
			&tx.ID, &tx.From, &tx.To, &tx.Amount, &tx.Fee,
			&tx.Data, &tx.Timestamp, &tx.Signature, &tx.BlockHash)

		if err != nil {
			return nil, err
		}

		transactions = append(transactions, tx)
	}

	return transactions, nil
}

// GetTransactionCount returns the total number of transactions
func (ps *PostgresStore) GetTransactionCount() (int64, error) {
	query := `SELECT COUNT(*) FROM transactions`

	var count int64
	err := ps.db.QueryRow(query).Scan(&count)
	return count, err
}

// SaveUser saves a user to the database
func (ps *PostgresStore) SaveUser(user *shared.User) error {
	query := `
		INSERT INTO users (id, username, email, password_hash, wallet_address, balance)
		VALUES ($1, $2, $3, $4, $5, $6)`

	_, err := ps.db.Exec(query,
		user.ID, user.Username, user.Email, user.Password,
		user.Address, user.Balance)

	return err
}

// GetUserByUsername retrieves a user by username
func (ps *PostgresStore) GetUserByUsername(username string) (*shared.User, error) {
	query := `SELECT id, username, email, password_hash, wallet_address, balance, created_at 
			  FROM users WHERE username = $1`

	var user shared.User
	err := ps.db.QueryRow(query, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.Password,
		&user.Address, &user.Balance, &user.Created)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	return &user, nil
}

// GetUserByID retrieves a user by ID
func (ps *PostgresStore) GetUserByID(id string) (*shared.User, error) {
	query := `SELECT id, username, email, password_hash, wallet_address, balance, created_at 
			  FROM users WHERE id = $1`

	var user shared.User
	err := ps.db.QueryRow(query, id).Scan(
		&user.ID, &user.Username, &user.Email, &user.Password,
		&user.Address, &user.Balance, &user.Created)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	return &user, nil
}

// UpdateUserBalance updates a user's balance
func (ps *PostgresStore) UpdateUserBalance(userID string, balance float64) error {
	query := `UPDATE users SET balance = $1 WHERE id = $2`

	_, err := ps.db.Exec(query, balance, userID)
	return err
}
