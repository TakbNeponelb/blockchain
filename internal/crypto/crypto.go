package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/bcrypt"
)

// Interface defines cryptographic operations
type Interface interface {
	HashPassword(password string) (string, error)
	CheckPasswordHash(password, hash string) bool
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
	GenerateHash(data string) string
	GenerateAddress() string
}

// Service implements cryptographic operations
type Service struct {
	encryptionKey []byte
	gcm           cipher.AEAD
}

// New creates a new crypto service
func New(key string) Interface {
	// Ensure key is 32 bytes for AES-256
	keyBytes := make([]byte, 32)
	copy(keyBytes, []byte(key))

	service := &Service{
		encryptionKey: keyBytes,
	}

	// Initialize AES-GCM
	block, err := aes.NewCipher(service.encryptionKey)
	if err != nil {
		panic(fmt.Sprintf("Failed to create cipher: %v", err))
	}

	service.gcm, err = cipher.NewGCM(block)
	if err != nil {
		panic(fmt.Sprintf("Failed to create GCM: %v", err))
	}

	return service
}

// HashPassword hashes a password using bcrypt
func (s *Service) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPasswordHash checks if password matches hash
func (s *Service) CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Encrypt encrypts plaintext using AES-GCM
func (s *Service) Encrypt(plaintext string) (string, error) {
	// Create a nonce
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt the data
	ciphertext := s.gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	// Return as hex string
	return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext using AES-GCM
func (s *Service) Decrypt(ciphertext string) (string, error) {
	// Decode hex string
	data, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	// Extract nonce
	nonceSize := s.gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext_bytes := data[:nonceSize], data[nonceSize:]

	// Decrypt
	plaintext, err := s.gcm.Open(nil, nonce, ciphertext_bytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// GenerateHash generates SHA256 hash of data
func (s *Service) GenerateHash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// GenerateAddress generates a random address
func (s *Service) GenerateAddress() string {
	// Generate 20 random bytes
	bytes := make([]byte, 20)
	rand.Read(bytes)

	// Return as hex string with prefix
	return "0x" + hex.EncodeToString(bytes)
}

// GenerateKeyPair generates a public/private key pair (simplified)
func (s *Service) GenerateKeyPair() (string, string, error) {
	// Generate private key (32 random bytes)
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return "", "", err
	}

	// Generate public key (hash of private key - simplified)
	publicKey := s.GenerateHash(hex.EncodeToString(privateKey))

	return hex.EncodeToString(privateKey), publicKey, nil
}

// SignData signs data with private key (simplified)
func (s *Service) SignData(data, privateKey string) (string, error) {
	// Simple signature: hash(data + private_key)
	signature := s.GenerateHash(data + privateKey)
	return signature, nil
}

// VerifySignature verifies a signature (simplified)
func (s *Service) VerifySignature(data, signature, publicKey string) bool {
	// This is a simplified verification - in production use proper ECDSA
	expectedSig := s.GenerateHash(data + publicKey)
	return signature == expectedSig
}
