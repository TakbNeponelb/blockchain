// internal/grpc_server/blockchain_server.go - gRPC сервер для блокчейна
package grpc_server

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"your-project/internal/auth"
	"your-project/internal/blockchain"
	"your-project/internal/models"
	pb "your-project/proto"
)

type BlockchainServer struct {
	pb.UnimplementedBlockchainServiceServer
	blockchain *blockchain.Blockchain
	auth       *auth.SecureAuth
}

func NewBlockchainServer(bc *blockchain.Blockchain, auth *auth.SecureAuth) *BlockchainServer {
	return &BlockchainServer{
		blockchain: bc,
		auth:       auth,
	}
}

// CreateTransaction - Создание транзакции
func (s *BlockchainServer) CreateTransaction(ctx context.Context, req *pb.CreateTransactionRequest) (*pb.TransactionResponse, error) {
	// Валидация входных данных
	if req.From == "" || req.To == "" || req.Amount <= 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid transaction parameters")
	}

	// Проверка баланса
	balance, err := s.blockchain.GetBalance(req.From)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get balance")
	}

	if balance < req.Amount {
		return nil, status.Error(codes.FailedPrecondition, "insufficient balance")
	}

	// Создание транзакции
	tx := &models.Transaction{
		ID:        generateTransactionID(),
		From:      req.From,
		To:        req.To,
		Amount:    req.Amount,
		Fee:       calculateFee(req.Amount),
		Data:      req.Data,
		Timestamp: time.Now(),
		Status:    "pending",
	}

	// Цифровая подпись транзакции
	if err := s.blockchain.SignTransaction(tx, req.PrivateKey); err != nil {
		return nil, status.Error(codes.Internal, "failed to sign transaction")
	}

	// Добавление в мемпул
	if err := s.blockchain.AddToMempool(tx); err != nil {
		return nil, status.Error(codes.Internal, "failed to add to mempool")
	}

	return &pb.TransactionResponse{
		TransactionId: tx.ID,
		Status:        tx.Status,
		Fee:           tx.Fee,
		Timestamp:     timestamppb.New(tx.Timestamp),
	}, nil
}

// GetTransaction - Получение транзакции по ID
func (s *BlockchainServer) GetTransaction(ctx context.Context, req *pb.GetTransactionRequest) (*pb.Transaction, error) {
	if req.TransactionId == "" {
		return nil, status.Error(codes.InvalidArgument, "transaction ID is required")
	}

	tx, err := s.blockchain.GetTransaction(req.TransactionId)
	if err != nil {
		if err == models.ErrTransactionNotFound {
			return nil, status.Error(codes.NotFound, "transaction not found")
		}
		return nil, status.Error(codes.Internal, "failed to get transaction")
	}

	return &pb.Transaction{
		Id:        tx.ID,
		From:      tx.From,
		To:        tx.To,
		Amount:    tx.Amount,
		Fee:       tx.Fee,
		Data:      tx.Data,
		Signature: tx.Signature,
		Status:    tx.Status,
		BlockHash: tx.BlockHash,
		Timestamp: timestamppb.New(tx.Timestamp),
	}, nil
}

// GetBlock - Получение блока
func (s *BlockchainServer) GetBlock(ctx context.Context, req *pb.GetBlockRequest) (*pb.Block, error) {
	var block *models.Block
	var err error

	if req.BlockHash != "" {
		block, err = s.blockchain.GetBlockByHash(req.BlockHash)
	} else if req.BlockNumber > 0 {
		block, err = s.blockchain.GetBlockByNumber(req.BlockNumber)
	} else {
		return nil, status.Error(codes.InvalidArgument, "either block hash or number is required")
	}

	if err != nil {
		if err == models.ErrBlockNotFound {
			return nil, status.Error(codes.NotFound, "block not found")
		}
		return nil, status.Error(codes.Internal, "failed to get block")
	}

	// Конвертация транзакций
	transactions := make([]*pb.Transaction, len(block.Transactions))
	for i, tx := range block.Transactions {
		transactions[i] = &pb.Transaction{
			Id:        tx.ID,
			From:      tx.From,
			To:        tx.To,
			Amount:    tx.Amount,
			Fee:       tx.Fee,
			Data:      tx.Data,
			Signature: tx.Signature,
			Status:    tx.Status,
			BlockHash: tx.BlockHash,
			Timestamp: timestamppb.New(tx.Timestamp),
		}
	}

	return &pb.Block{
		Hash:         block.Hash,
		PreviousHash: block.PreviousHash,
		MerkleRoot:   block.MerkleRoot,
		Number:       block.Number,
		Timestamp:    timestamppb.New(block.Timestamp),
		Nonce:        block.Nonce,
		Difficulty:   int32(block.Difficulty),
		Transactions: transactions,
		Miner:        block.Miner,
		Reward:       block.Reward,
		Size:         int32(block.Size),
		GasUsed:      block.GasUsed,
		GasLimit:     block.GasLimit,
	}, nil
}

// GetBalance - Получение баланса
func (s *BlockchainServer) GetBalance(ctx context.Context, req *pb.GetBalanceRequest) (*pb.BalanceResponse, error) {
	if req.Address == "" {
		return nil, status.Error(codes.InvalidArgument, "address is required")
	}

	balance, err := s.blockchain.GetBalance(req.Address)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get balance")
	}

	// Получение pending транзакций
	pendingBalance, err := s.blockchain.GetPendingBalance(req.Address)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get pending balance")
	}

	return &pb.BalanceResponse{
		Address:        req.Address,
		Balance:        balance,
		PendingBalance: pendingBalance,
		Currency:       "COIN",
	}, nil
}

// GetChainInfo - Информация о блокчейне
func (s *BlockchainServer) GetChainInfo(ctx context.Context, req *pb.Empty) (*pb.ChainInfoResponse, error) {
	info, err := s.blockchain.GetChainInfo()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get chain info")
	}

	return &pb.ChainInfoResponse{
		Height:          info.Height,
		BestBlockHash:   info.BestBlockHash,
		Difficulty:      int32(info.Difficulty),
		TotalWork:       info.TotalWork,
		NetworkHashRate: info.NetworkHashRate,
		MempoolSize:     int32(info.MempoolSize),
		PeerCount:       int32(info.PeerCount),
		Version:         info.Version,
		NetworkId:       info.NetworkID,
	}, nil
}

// MineBlock - Майнинг блока (только для авторизованных майнеров)
func (s *BlockchainServer) MineBlock(ctx context.Context, req *pb.MineBlockRequest) (*pb.Block, error) {
	// Проверка прав майнинга
	claims, ok := ctx.Value("claims").(*auth.TokenClaims)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	if !contains(claims.Roles, "miner") {
		return nil, status.Error(codes.PermissionDenied, "mining permission required")
	}

	// Майнинг нового блока
	block, err := s.blockchain.MineBlock(claims.UserID, req.MinerAddress)
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to mine block: %v", err))
	}

	// Конвертация транзакций
	transactions := make([]*pb.Transaction, len(block.Transactions))
	for i, tx := range block.Transactions {
		transactions[i] = &pb.Transaction{
			Id:        tx.ID,
			From:      tx.From,
			To:        tx.To,
			Amount:    tx.Amount,
			Fee:       tx.Fee,
			Data:      tx.Data,
			Signature: tx.Signature,
			Status:    tx.Status,
			BlockHash: tx.BlockHash,
			Timestamp: timestamppb.New(tx.Timestamp),
		}
	}

	return &pb.Block{
		Hash:         block.Hash,
		PreviousHash: block.PreviousHash,
		MerkleRoot:   block.MerkleRoot,
		Number:       block.Number,
		Timestamp:    timestamppb.New(block.Timestamp),
		Nonce:        block.Nonce,
		Difficulty:   int32(block.Difficulty),
		Transactions: transactions,
		Miner:        block.Miner,
		Reward:       block.Reward,
		Size:         int32(block.Size),
		GasUsed:      block.GasUsed,
		GasLimit:     block.GasLimit,
	}, nil
}

// StreamBlocks - Стрим новых блоков
func (s *BlockchainServer) StreamBlocks(req *pb.Empty, stream pb.BlockchainService_StreamBlocksServer) error {
	// Подписка на новые блоки
	blockChan := s.blockchain.SubscribeToBlocks()
	defer s.blockchain.UnsubscribeFromBlocks(blockChan)

	for {
		select {
		case block := <-blockChan:
			// Конвертация транзакций
			transactions := make([]*pb.Transaction, len(block.Transactions))
			for i, tx := range block.Transactions {
				transactions[i] = &pb.Transaction{
					Id:        tx.ID,
					From:      tx.From,
					To:        tx.To,
					Amount:    tx.Amount,
					Fee:       tx.Fee,
					Data:      tx.Data,
					Signature: tx.Signature,
					Status:    tx.Status,
					BlockHash: tx.BlockHash,
					Timestamp: timestamppb.New(tx.Timestamp),
				}
			}

			pbBlock := &pb.Block{
				Hash:         block.Hash,
				PreviousHash: block.PreviousHash,
				MerkleRoot:   block.MerkleRoot,
				Number:       block.Number,
				Timestamp:    timestamppb.New(block.Timestamp),
				Nonce:        block.Nonce,
				Difficulty:   int32(block.Difficulty),
				Transactions: transactions,
				Miner:        block.Miner,
				Reward:       block.Reward,
				Size:         int32(block.Size),
				GasUsed:      block.GasUsed,
				GasLimit:     block.GasLimit,
			}

			if err := stream.Send(pbBlock); err != nil {
				return err
			}

		case <-stream.Context().Done():
			return nil
		}
	}
}

// ValidateTransaction - Валидация транзакции
func (s *BlockchainServer) ValidateTransaction(ctx context.Context, req *pb.Transaction) (*pb.ValidationResponse, error) {
	tx := &models.Transaction{
		ID:        req.Id,
		From:      req.From,
		To:        req.To,
		Amount:    req.Amount,
		Fee:       req.Fee,
		Data:      req.Data,
		Signature: req.Signature,
		Timestamp: req.Timestamp.AsTime(),
	}

	valid, errors := s.blockchain.ValidateTransaction(tx)

	return &pb.ValidationResponse{
		Valid:  valid,
		Errors: errors,
	}, nil
}

// internal/grpc_server/auth_server.go - gRPC сервер для аутентификации
type AuthServer struct {
	pb.UnimplementedAuthServiceServer
	auth *auth.SecureAuth
}

func NewAuthServer(auth *auth.SecureAuth) *AuthServer {
	return &AuthServer{
		auth: auth,
	}
}

// Login - Вход пользователя
func (s *AuthServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	if req.Email == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "email and password are required")
	}

	// Проверка блокировки аккаунта
	locked, duration, err := s.auth.IsAccountLocked(req.Email)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to check account status")
	}
	if locked {
		return nil, status.Error(codes.PermissionDenied, fmt.Sprintf("account locked for %v", duration))
	}

	// Получение пользователя из базы данных (здесь нужна реализация)
	user, err := getUserByEmail(req.Email)
	if err != nil {
		// Отслеживание неудачной попытки
		s.auth.TrackLoginAttempt(auth.LoginAttempt{
			IP:        getClientIP(ctx),
			UserID:    req.Email,
			Success:   false,
			UserAgent: getUserAgent(ctx),
			Timestamp: time.Now(),
		})
		return nil, status.Error(codes.NotFound, "user not found")
	}

	// Проверка пароля
	if !s.auth.VerifyPassword(req.Password, user.PasswordHash) {
		s.auth.TrackLoginAttempt(auth.LoginAttempt{
			IP:        getClientIP(ctx),
			UserID:    user.ID,
			Success:   false,
			UserAgent: getUserAgent(ctx),
			Timestamp: time.Now(),
		})
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	// Проверка 2FA если требуется
	if user.TwoFactorEnabled && req.TotpCode == "" {
		return &pb.LoginResponse{
			RequiresTwoFactor: true,
			Message:           "TOTP code required",
		}, nil
	}

	if user.TwoFactorEnabled {
		if err := s.auth.Verify2FA(user.ID, req.TotpCode); err != nil {
			s.auth.TrackLoginAttempt(auth.LoginAttempt{
				IP:        getClientIP(ctx),
				UserID:    user.ID,
				Success:   false,
				UserAgent: getUserAgent(ctx),
				Timestamp: time.Now(),
			})
			return nil, status.Error(codes.Unauthenticated, "invalid 2FA code")
		}
	}

	// Генерация токенов
	tokenPair, err := s.auth.GenerateTokenPair(user, req.DeviceId, getClientIP(ctx))
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate tokens")
	}

	// Отслеживание успешной попытки
	s.auth.TrackLoginAttempt(auth.LoginAttempt{
		IP:        getClientIP(ctx),
		UserID:    user.ID,
		Success:   true,
		UserAgent: getUserAgent(ctx),
		Timestamp: time.Now(),
	})

	return &pb.LoginResponse{
		AccessToken:       tokenPair.AccessToken,
		RefreshToken:      tokenPair.RefreshToken,
		ExpiresIn:         int32(tokenPair.ExpiresIn),
		TokenType:         tokenPair.TokenType,
		RequiresTwoFactor: false,
		User: &pb.User{
			Id:       user.ID,
			Email:    user.Email,
			Roles:    user.Roles,
			Created:  timestamppb.New(user.CreatedAt),
			LastSeen: timestamppb.New(user.LastSeen),
		},
	}, nil
}

// RefreshToken - Обновление токена
func (s *AuthServer) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.TokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh token is required")
	}

	// Логика обновления токена (нужна реализация)
	tokenPair, err := s.auth.RefreshAccessToken(req.RefreshToken, getClientIP(ctx))
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
	}

	return &pb.TokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    int32(tokenPair.ExpiresIn),
		TokenType:    tokenPair.TokenType,
	}, nil
}

// Logout - Выход пользователя
func (s *AuthServer) Logout(ctx context.Context, req *pb.Empty) (*pb.Empty, error) {
	claims, ok := ctx.Value("claims").(*auth.TokenClaims)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	// Отзыв сессии
	if err := s.auth.RevokeSession(claims.SessionID); err != nil {
		return nil, status.Error(codes.Internal, "failed to logout")
	}

	return &pb.Empty{}, nil
}

// Setup2FA - Настройка двухфакторной аутентификации
func (s *AuthServer) Setup2FA(ctx context.Context, req *pb.Empty) (*pb.Setup2FAResponse, error) {
	claims, ok := ctx.Value("claims").(*auth.TokenClaims)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	setup, err := s.auth.Setup2FA(claims.UserID)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to setup 2FA")
	}

	return &pb.Setup2FAResponse{
		Secret:      setup.Secret,
		QrCodeUrl:   setup.QRCodeURL,
		BackupCodes: setup.BackupCodes,
	}, nil
}

// Вспомогательные функции
func generateTransactionID() string {
	// Реализация генерации ID транзакции
	return fmt.Sprintf("tx_%d", time.Now().UnixNano())
}

func calculateFee(amount float64) float64 {
	// Простая логика расчета комиссии (0.1%)
	return amount * 0.001
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func getClientIP(ctx context.Context) string {
	// Извлечение IP адреса из контекста gRPC
	// Реализация зависит от middleware
	return "127.0.0.1" // placeholder
}

func getUserAgent(ctx context.Context) string {
	// Извлечение User-Agent из контекста gRPC
	return "unknown" // placeholder
}

func getUserByEmail(email string) (*models.User, error) {
	// Заглушка - нужна реализация с обращением к базе данных
	return nil, fmt.Errorf("not implemented")
}
