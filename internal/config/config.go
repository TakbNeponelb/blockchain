// internal/config/config.go - Конфигурация с безопасными настройками
package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Database   DatabaseConfig
	Redis      RedisConfig
	Blockchain BlockchainConfig
	Auth       AuthConfig
	P2P        P2PConfig
	GRPC       GRPCConfig
	HTTP       HTTPConfig
	TLS        TLSConfig
	RateLimit  RateLimitConfig
	CORS       CORSConfig
}

type DatabaseConfig struct {
	Host        string
	Port        int
	User        string
	Password    string
	DBName      string
	SSLMode     string
	MaxConns    int
	MaxIdle     int
	ConnTimeout time.Duration
}

type RedisConfig struct {
	Addr     string
	Password string
	DB       int
}

type AuthConfig struct {
	JWTSecret          string
	JWTExpiration      time.Duration
	RefreshTokenExpiry time.Duration
	PasswordMinLength  int
	MaxLoginAttempts   int
	LockoutDuration    time.Duration
	TwoFactorRequired  bool
	SessionTimeout     time.Duration
}

type BlockchainConfig struct {
	GenesisBlock   string
	Difficulty     int
	MiningReward   float64
	BlockSize      int
	NetworkID      string
	ConsensusType  string // "pow" or "pos"
	ValidatorStake float64
}

type P2PConfig struct {
	Port           int
	MaxPeers       int
	BootstrapNodes []string
	NetworkKey     string
	TLSEnabled     bool
}

type GRPCConfig struct {
	Port int
}

type HTTPConfig struct {
	Port int
}

type TLSConfig struct {
	CertFile string
	KeyFile  string
}

type RateLimitConfig struct {
	RequestsPerMinute int
	BurstSize         int
}

type CORSConfig struct {
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
}

func Load() *Config {
	return &Config{
		Database: DatabaseConfig{
			Host:        getEnv("DB_HOST", "localhost"),
			Port:        getEnvInt("DB_PORT", 5432),
			User:        getEnv("DB_USER", "blockchain"),
			Password:    getEnv("DB_PASSWORD", ""),
			DBName:      getEnv("DB_NAME", "blockchain"),
			SSLMode:     getEnv("DB_SSL_MODE", "require"),
			MaxConns:    getEnvInt("DB_MAX_CONNS", 25),
			MaxIdle:     getEnvInt("DB_MAX_IDLE", 5),
			ConnTimeout: getEnvDuration("DB_CONN_TIMEOUT", 30*time.Second),
		},
		Redis: RedisConfig{
			Addr:     getEnv("REDIS_ADDR", "localhost:6379"),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getEnvInt("REDIS_DB", 0),
		},
		Auth: AuthConfig{
			JWTSecret:          getEnv("JWT_SECRET", ""),
			JWTExpiration:      getEnvDuration("JWT_EXPIRATION", 15*time.Minute),
			RefreshTokenExpiry: getEnvDuration("REFRESH_TOKEN_EXPIRY", 7*24*time.Hour),
			PasswordMinLength:  getEnvInt("PASSWORD_MIN_LENGTH", 12),
			MaxLoginAttempts:   getEnvInt("MAX_LOGIN_ATTEMPTS", 5),
			LockoutDuration:    getEnvDuration("LOCKOUT_DURATION", 30*time.Minute),
			TwoFactorRequired:  getEnvBool("TWO_FACTOR_REQUIRED", true),
			SessionTimeout:     getEnvDuration("SESSION_TIMEOUT", 24*time.Hour),
		},
		Blockchain: BlockchainConfig{
			Difficulty:     getEnvInt("BLOCKCHAIN_DIFFICULTY", 4),
			MiningReward:   getEnvFloat("MINING_REWARD", 50.0),
			BlockSize:      getEnvInt("BLOCK_SIZE", 1024*1024), // 1MB
			NetworkID:      getEnv("NETWORK_ID", "mainnet"),
			ConsensusType:  getEnv("CONSENSUS_TYPE", "pow"),
			ValidatorStake: getEnvFloat("VALIDATOR_STAKE", 1000.0),
		},
		P2P: P2PConfig{
			Port:       getEnvInt("P2P_PORT", 8001),
			MaxPeers:   getEnvInt("P2P_MAX_PEERS", 50),
			NetworkKey: getEnv("P2P_NETWORK_KEY", ""),
			TLSEnabled: getEnvBool("P2P_TLS_ENABLED", true),
		},
		GRPC: GRPCConfig{
			Port: getEnvInt("GRPC_PORT", 8002),
		},
		HTTP: HTTPConfig{
			Port: getEnvInt("HTTP_PORT", 8080),
		},
		TLS: TLSConfig{
			CertFile: getEnv("TLS_CERT_FILE", "certs/server.crt"),
			KeyFile:  getEnv("TLS_KEY_FILE", "certs/server.key"),
		},
		RateLimit: RateLimitConfig{
			RequestsPerMinute: getEnvInt("RATE_LIMIT_RPM", 100),
			BurstSize:         getEnvInt("RATE_LIMIT_BURST", 10),
		},
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvFloat(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if floatValue, err := strconv.ParseFloat(value, 64); err == nil {
			return floatValue
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}
