package main

import (
	"blockchain/internal/api"
	"blockchain/internal/auth"
	"blockchain/internal/blockchain"
	"blockchain/internal/consensus"
	"blockchain/internal/crypto"
	"blockchain/internal/datastore"
	"blockchain/internal/p2p"
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

// @title Blockchain API
// @version 1.0
// @description A minimal and extendable blockchain service
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8080
// @BasePath /api/v1

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	// Database configuration
	dbHost := getEnv("DB_HOST", "localhost")
	dbPort := getEnv("DB_PORT", "5432")
	dbName := getEnv("DB_NAME", "blockchain")
	dbUser := getEnv("DB_USER", "blockchain")
	dbPassword := getEnv("DB_PASSWORD", "blockchain123")

	// Connect to database
	db, err := sql.Open("postgres",
		"host="+dbHost+" port="+dbPort+" user="+dbUser+" password="+dbPassword+" dbname="+dbName+" sslmode=disable")
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	// Test database connection
	if err := db.Ping(); err != nil {
		log.Fatal("Failed to ping database:", err)
	}

	// Initialize datastore
	dataStore := datastore.New(db)
	if err := dataStore.InitTables(); err != nil {
		log.Fatal("Failed to initialize database tables:", err)
	}

	// Initialize crypto service
	encryptionKey := getEnv("ENCRYPTION_KEY", "your-32-byte-encryption-key-here")
	cryptoService := crypto.New(encryptionKey)

	// Initialize consensus engine
	consensusEngine := consensus.NewPoW(4) // difficulty level 4

	// Initialize blockchain
	bc := blockchain.New(dataStore, cryptoService, consensusEngine)
	if err := bc.Initialize(); err != nil {
		log.Fatal("Failed to initialize blockchain:", err)
	}

	// Initialize P2P network
	p2pPort := getEnv("P2P_PORT", "9090")
	p2pNetwork := p2p.New(p2pPort, bc)
	go p2pNetwork.Start()

	// Initialize auth service
	jwtSecret := getEnv("JWT_SECRET", "your-jwt-secret-key-change-in-production")
	authService := auth.New(jwtSecret, dataStore)

	// Initialize API server
	apiServer := api.New(bc, authService, p2pNetwork)

	// Set Gin mode
	if getEnv("GIN_MODE", "debug") == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Setup router
	router := apiServer.SetupRoutes()

	// Create HTTP server
	srv := &http.Server{
		Addr:    ":" + getEnv("PORT", "8080"),
		Handler: router,
	}

	// Start server in goroutine
	go func() {
		log.Println("Starting blockchain service on", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server:", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	p2pNetwork.Stop()
	log.Println("Server exited")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
