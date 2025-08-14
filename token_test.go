package gosjwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTokenReleaseAndParse(t *testing.T) {
	// 初始化配置
	config := &Config{
		SigningKey: []byte("test-secret-key"),
		Issuer:     "test-issuer",
		Expires:    3600, // 1小时
		Cache: CacheConfig{
			Type: "memory",
		},
		GracePeriod:            300, // 5分钟宽限期
		BlacklistCleanDuration: 5,   // 5分钟清理间隔
	}

	// 创建JWT处理器
	handler, err := NewJwtHandler(config)
	assert.NoError(t, err)
	defer handler.Close()

	// 测试用例1: 正常发放和解析Token
	t.Run("NormalToken", func(t *testing.T) {
		userID := uint(123)
		token, err := handler.ReleaseToken(userID)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// 解析Token
		parsedToken, claims, err := handler.ParseToken(token)
		assert.NoError(t, err)
		assert.True(t, parsedToken.Valid)
		assert.Equal(t, userID, claims.UserId)
		assert.Equal(t, config.Issuer, claims.Issuer)
	})

	// 测试用例2: 过期Token
	t.Run("ExpiredToken", func(t *testing.T) {
		// 创建一个立即过期的Token
		expiredConfig := &Config{
			SigningKey: []byte("test-secret-key"),
			Issuer:     "test-issuer",
			Expires:    -1, // 立即过期
			Cache: CacheConfig{
				Type: "memory",
			},
			BlacklistCleanDuration: 5, // 5分钟清理间隔
		}

		expiredHandler, err := NewJwtHandler(expiredConfig)
		assert.NoError(t, err)
		defer expiredHandler.Close()

		userID := uint(456)
		token, err := expiredHandler.ReleaseToken(userID)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// 解析应该返回过期错误
		_, _, err = expiredHandler.ParseToken(token)
		assert.Error(t, err)
		assert.True(t, isExpiredError(err))
	})

	// 测试用例3: 撤销Token
	t.Run("RevokeToken", func(t *testing.T) {
		userID := uint(789)
		token, err := handler.ReleaseToken(userID)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// 撤销Token
		err = handler.RevokeToken(token)
		assert.NoError(t, err)

		// 解析应该返回Token已被撤销
		_, _, err = handler.ParseToken(token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token已被撤销")
	})

	// 测试用例4: 无效Token
	t.Run("InvalidToken", func(t *testing.T) {
		invalidToken := "invalid.token.string"
		_, _, err := handler.ParseToken(invalidToken)
		assert.Error(t, err)
	})
}
