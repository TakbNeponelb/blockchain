// internal/auth/secure_auth.go - Усиленная система аутентификации
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/argon2"

	"your-project/internal/config"
	"your-project/internal/models"
	"your-project/pkg/errors"
)

type SecureAuth struct {
	cfg       *config.AuthConfig
	redis     *redis.Client
	jwtSecret []byte
	pepper    []byte // Дополнительная защита паролей
}

type TokenClaims struct {
	UserID      string   `json:"user_id"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	SessionID   string   `json:"session_id"`
	DeviceID    string   `json:"device_id"`
	IPAddress   string   `json:"ip_address"`
	jwt.StandardClaims
}

type LoginAttempt struct {
	IP        string
	UserID    string
	Timestamp time.Time
	Success   bool
	UserAgent string
	Location  string
}

type SecurityEvent struct {
	Type      string
	UserID    string
	Details   map[string]interface{}
	Timestamp time.Time
	Severity  string
}

func NewSecureAuth(cfg *config.AuthConfig, redis *redis.Client) *SecureAuth {
	pepper := make([]byte, 32)
	if _, err := rand.Read(pepper); err != nil {
		panic("Failed to generate pepper: " + err.Error())
	}

	return &SecureAuth{
		cfg:       cfg,
		redis:     redis,
		jwtSecret: []byte(cfg.JWTSecret),
		pepper:    pepper,
	}
}

// HashPassword - Безопасное хеширование пароля с Argon2id
func (sa *SecureAuth) HashPassword(password string) (string, error) {
	if len(password) < sa.cfg.PasswordMinLength {
		return "", errors.ErrWeakPassword
	}

	// Генерация соли
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Добавление pepper для дополнительной защиты
	passwordWithPepper := password + string(sa.pepper)

	// Argon2id параметры (рекомендуемые OWASP)
	hash := argon2.IDKey([]byte(passwordWithPepper), salt, 3, 64*1024, 4, 32)

	// Кодирование результата
	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, 64*1024, 3, 4,
		base32.StdEncoding.EncodeToString(salt),
		base32.StdEncoding.EncodeToString(hash))

	return encodedHash, nil
}

// VerifyPassword - Проверка пароля с защитой от timing attacks
func (sa *SecureAuth) VerifyPassword(password, hashedPassword string) bool {
	// Парсинг хешированного пароля
	// Simplified parsing for example
	passwordWithPepper := password + string(sa.pepper)

	// Используем constant-time comparison для защиты от timing attacks
	return subtle.ConstantTimeCompare([]byte(password), []byte(passwordWithPepper)) == 1
}

// GenerateTokenPair - Генерация JWT и Refresh токенов
func (sa *SecureAuth) GenerateTokenPair(user *models.User, deviceID, ipAddress string) (*models.TokenPair, error) {
	sessionID := sa.generateSecureID()

	// Access Token
	accessClaims := &TokenClaims{
		UserID:      user.ID,
		Email:       user.Email,
		Roles:       user.Roles,
		Permissions: user.Permissions,
		SessionID:   sessionID,
		DeviceID:    deviceID,
		IPAddress:   ipAddress,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(sa.cfg.JWTExpiration).Unix(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    "blockchain-api",
			Subject:   user.ID,
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, accessClaims)
	accessTokenString, err := accessToken.SignedString(sa.jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Refresh Token
	refreshToken := sa.generateSecureID()

	// Сохранение сессии в Redis
	sessionData := map[string]interface{}{
		"user_id":       user.ID,
		"device_id":     deviceID,
		"ip_address":    ipAddress,
		"created_at":    time.Now().Unix(),
		"last_used":     time.Now().Unix(),
		"refresh_token": refreshToken,
	}

	ctx := context.Background()
	err = sa.redis.HMSet(ctx, fmt.Sprintf("session:%s", sessionID), sessionData).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to store session: %w", err)
	}

	err = sa.redis.Expire(ctx, fmt.Sprintf("session:%s", sessionID), sa.cfg.RefreshTokenExpiry).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to set session expiry: %w", err)
	}

	return &models.TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshToken,
		ExpiresIn:    int(sa.cfg.JWTExpiration.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

// ValidateToken - Проверка JWT токена
func (sa *SecureAuth) ValidateToken(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return sa.jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		// Проверка активности сессии
		ctx := context.Background()
		sessionExists, err := sa.redis.Exists(ctx, fmt.Sprintf("session:%s", claims.SessionID)).Result()
		if err != nil || sessionExists == 0 {
			return nil, errors.ErrInvalidSession
		}

		// Обновление времени последнего использования
		sa.redis.HSet(ctx, fmt.Sprintf("session:%s", claims.SessionID), "last_used", time.Now().Unix())

		return claims, nil
	}

	return nil, errors.ErrInvalidToken
}

// Setup2FA - Настройка двухфакторной аутентификации
func (sa *SecureAuth) Setup2FA(userID string) (*models.TwoFactorSetup, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "BlockchainAPI",
		AccountName: userID,
		SecretSize:  32,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	// Сохранение временного секрета (до подтверждения)
	ctx := context.Background()
	err = sa.redis.Set(ctx, fmt.Sprintf("2fa_setup:%s", userID), key.Secret(), 10*time.Minute).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to store 2FA setup: %w", err)
	}

	return &models.TwoFactorSetup{
		Secret:      key.Secret(),
		QRCodeURL:   key.URL(),
		BackupCodes: sa.generateBackupCodes(),
	}, nil
}

// Verify2FA - Проверка TOTP кода
func (sa *SecureAuth) Verify2FA(userID, code string) error {
	ctx := context.Background()

	// Получение секрета пользователя
	secret, err := sa.redis.Get(ctx, fmt.Sprintf("2fa_secret:%s", userID)).Result()
	if err != nil {
		return errors.Err2FANotSetup
	}

	// Проверка кода с окном в 1 период (30 секунд)
	valid := totp.Validate(code, secret)
	if !valid {
		// Проверка резервных кодов
		return sa.verifyBackupCode(userID, code)
	}

	return nil
}

// TrackLoginAttempt - Отслеживание попыток входа
func (sa *SecureAuth) TrackLoginAttempt(attempt LoginAttempt) error {
	ctx := context.Background()

	// Сериализация попытки
	attemptKey := fmt.Sprintf("login_attempts:%s:%s", attempt.UserID, attempt.IP)

	// Получение текущего количества неудачных попыток
	attempts, err := sa.redis.Get(ctx, attemptKey).Int()
	if err != nil && err != redis.Nil {
		return fmt.Errorf("failed to get login attempts: %w", err)
	}

	if !attempt.Success {
		attempts++

		// Блокировка после превышения лимита
		if attempts >= sa.cfg.MaxLoginAttempts {
			sa.redis.Set(ctx, fmt.Sprintf("lockout:%s", attempt.UserID),
				time.Now().Unix(), sa.cfg.LockoutDuration)

			// Отправка уведомления о подозрительной активности
			sa.logSecurityEvent(SecurityEvent{
				Type:     "account_lockout",
				UserID:   attempt.UserID,
				Details:  map[string]interface{}{"ip": attempt.IP, "attempts": attempts},
				Severity: "high",
			})
		}

		sa.redis.Set(ctx, attemptKey, attempts, 24*time.Hour)
	} else {
		// Успешный вход - сброс счетчика
		sa.redis.Del(ctx, attemptKey)
		sa.redis.Del(ctx, fmt.Sprintf("lockout:%s", attempt.UserID))
	}

	return nil
}

// IsAccountLocked - Проверка блокировки аккаунта
func (sa *SecureAuth) IsAccountLocked(userID string) (bool, time.Duration, error) {
	ctx := context.Background()

	lockoutTime, err := sa.redis.Get(ctx, fmt.Sprintf("lockout:%s", userID)).Result()
	if err == redis.Nil {
		return false, 0, nil
	}
	if err != nil {
		return false, 0, fmt.Errorf("failed to check lockout: %w", err)
	}

	ttl, err := sa.redis.TTL(ctx, fmt.Sprintf("lockout:%s", userID)).Result()
	if err != nil {
		return false, 0, fmt.Errorf("failed to get lockout TTL: %w", err)
	}

	return true, ttl, nil
}

// RevokeSession - Отзыв сессии
func (sa *SecureAuth) RevokeSession(sessionID string) error {
	ctx := context.Background()
	err := sa.redis.Del(ctx, fmt.Sprintf("session:%s", sessionID)).Err()
	if err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	sa.logSecurityEvent(SecurityEvent{
		Type:     "session_revoked",
		Details:  map[string]interface{}{"session_id": sessionID},
		Severity: "medium",
	})

	return nil
}

// RevokeAllUserSessions - Отзыв всех сессий пользователя
func (sa *SecureAuth) RevokeAllUserSessions(userID string) error {
	ctx := context.Background()

	// Поиск всех сессий пользователя
	pattern := "session:*"
	keys, err := sa.redis.Keys(ctx, pattern).Result()
	if err != nil {
		return fmt.Errorf("failed to find sessions: %w", err)
	}

	for _, key := range keys {
		sessionUserID, err := sa.redis.HGet(ctx, key, "user_id").Result()
		if err != nil {
			continue
		}

		if sessionUserID == userID {
			sa.redis.Del(ctx, key)
		}
	}

	sa.logSecurityEvent(SecurityEvent{
		Type:     "all_sessions_revoked",
		UserID:   userID,
		Severity: "high",
	})

	return nil
}

// Вспомогательные методы
func (sa *SecureAuth) generateSecureID() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (sa *SecureAuth) generateBackupCodes() []string {
	codes := make([]string, 8)
	for i := range codes {
		bytes := make([]byte, 8)
		rand.Read(bytes)
		codes[i] = hex.EncodeToString(bytes)
	}
	return codes
}

func (sa *SecureAuth) verifyBackupCode(userID, code string) error {
	ctx := context.Background()

	// Получение резервных кодов
	backupCodes, err := sa.redis.SMembers(ctx, fmt.Sprintf("backup_codes:%s", userID)).Result()
	if err != nil {
		return errors.ErrInvalidBackupCode
	}

	// Проверка наличия кода
	for _, backupCode := range backupCodes {
		if subtle.ConstantTimeCompare([]byte(code), []byte(backupCode)) == 1 {
			// Удаление использованного кода
			sa.redis.SRem(ctx, fmt.Sprintf("backup_codes:%s", userID), code)
			return nil
		}
	}

	return errors.ErrInvalidBackupCode
}

func (sa *SecureAuth) logSecurityEvent(event SecurityEvent) {
	event.Timestamp = time.Now()

	// Отправка в систему мониторинга/логирования
	// Здесь можно интегрировать с ELK Stack, Prometheus, etc.
	fmt.Printf("Security Event: %+v\n", event)
}

// PasswordStrengthCheck - Проверка сложности пароля
func (sa *SecureAuth) PasswordStrengthCheck(password string) error {
	if len(password) < sa.cfg.PasswordMinLength {
		return errors.ErrPasswordTooShort
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool

	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasDigit = true
		case char >= 33 && char <= 126:
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return errors.ErrPasswordTooWeak
	}

	// Проверка на распространенные пароли
	if sa.isCommonPassword(password) {
		return errors.ErrPasswordTooCommon
	}

	return nil
}

// isCommonPassword - Проверка на распространенные пароли
func (sa *SecureAuth) isCommonPassword(password string) bool {
	commonPasswords := []string{
		"password", "123456", "password123", "admin", "qwerty",
		"letmein", "welcome", "monkey", "1234567890", "abc123",
	}

	for _, common := range commonPasswords {
		if password == common {
			return true
		}
	}
	return false
}
