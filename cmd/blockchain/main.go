// main.go - Главная точка входа
package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"your-project/internal/api"
	"your-project/internal/auth"
	"your-project/internal/blockchain"
	"your-project/internal/config"
	"your-project/internal/datastore"
	"your-project/internal/grpc_server"
	"your-project/internal/middleware"
	"your-project/internal/p2p"
	pb "your-project/proto"
)

func main() {
	// Загрузка конфигурации
	cfg := config.Load()

	// Инициализация базы данных
	db, err := datastore.NewPostgreSQL(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Инициализация Redis для сессий
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	})

	// Инициализация блокчейна
	bc := blockchain.New(db, cfg.Blockchain)

	// Инициализация аутентификации с повышенной безопасностью
	authService := auth.NewSecureAuth(cfg.Auth, rdb)

	// Инициализация P2P сети с шифрованием
	p2pNode := p2p.NewSecureNode(cfg.P2P, bc)

	// Запуск gRPC сервера
	go startGRPCServer(cfg, bc, authService)

	// Запуск REST API сервера
	go startHTTPServer(cfg, bc, authService)

	// Запуск P2P узла
	go p2pNode.Start()

	// Graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	log.Println("Shutting down...")
	p2pNode.Stop()
}

func startGRPCServer(cfg *config.Config, bc *blockchain.Blockchain, auth *auth.SecureAuth) {
	// Загрузка TLS сертификатов
	creds, err := credentials.NewServerTLSFromFile(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		log.Fatalf("Failed to load TLS credentials: %v", err)
	}

	// Настройка gRPC сервера с keepalive
	s := grpc.NewServer(
		grpc.Creds(creds),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 15 * time.Second,
			MaxConnectionAge:  30 * time.Second,
			Time:              5 * time.Second,
			Timeout:           1 * time.Second,
		}),
		grpc.UnaryInterceptor(middleware.GRPCAuthInterceptor(auth)),
		grpc.StreamInterceptor(middleware.GRPCStreamAuthInterceptor(auth)),
	)

	// Регистрация сервисов
	pb.RegisterBlockchainServiceServer(s, grpc_server.NewBlockchainServer(bc, auth))
	pb.RegisterAuthServiceServer(s, grpc_server.NewAuthServer(auth))

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.GRPC.Port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Printf("gRPC server listening on :%d", cfg.GRPC.Port)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve gRPC: %v", err)
	}
}

func startHTTPServer(cfg *config.Config, bc *blockchain.Blockchain, auth *auth.SecureAuth) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()

	// Безопасные middleware
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.RateLimit(cfg.RateLimit))
	r.Use(middleware.CORS(cfg.CORS))
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	// Инициализация API роутов
	api.SetupRoutes(r, bc, auth)

	// HTTPS сервер
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.HTTP.Port),
		Handler: r,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{
				tls.CurveP521,
				tls.CurveP384,
				tls.CurveP256,
			},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_AES_128_GCM_SHA256,
			},
		},
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	log.Printf("HTTPS server listening on :%d", cfg.HTTP.Port)
	log.Fatal(server.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile))
}
