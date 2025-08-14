/**
 * @Author: guxline zjguoxin@163.com
 * @Date: 2025/7/8 08:13:24
 * @LastEditors: guxline zjguoxin@163.com
 * @LastEditTime: 2025/7/8 08:13:24
 * Description:
 * Copyright: Copyright (©) 2025 中易综服. All rights reserved.
 */
package gosjwt

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// 测试辅助函数
func setupTestRouter() (*gin.Engine, *JwtHandler) {
	config := &Config{
		SigningKey:             []byte("test-secret-key"),
		Issuer:                 "test-issuer",
		Expires:                1, // 1秒过期便于测试
		GracePeriod:            5, // 5秒宽限期
		BlacklistCleanDuration: 1, // 1分钟清理间隔
		Cache: CacheConfig{
			Type: "memory", // 使用内存缓存便于测试
		},
	}

	handler, _ := NewJwtHandler(config)

	r := gin.New()
	r.Use(handler.GinMiddleware())
	r.GET("/protected", func(c *gin.Context) {
		userID, _ := c.Get("userID")
		c.JSON(http.StatusOK, gin.H{"userID": userID})
	})

	return r, handler
}

// 正常 Token 测试
// func TestValidToken(t *testing.T) {
// 	r, handler := setupTestRouter() // 这里正确调用了setupTestRouter()

// 	// 生成有效Token
// 	userID := uint(1001)
// 	token, err := handler.ReleaseToken(userID)
// 	assert.NoError(t, err)

// 	req := httptest.NewRequest("GET", "/protected", nil)
// 	req.Header.Set("Authorization", "Bearer "+token)
// 	w := httptest.NewRecorder()

// 	r.ServeHTTP(w, req)

// 	assert.Equal(t, http.StatusOK, w.Code)
// 	assert.Contains(t, w.Body.String(), `"userID":1001`)
// }

// // 缺少 Authorization 头测试
// func TestMissingAuthHeader(t *testing.T) {
// 	r, _ := setupTestRouter()

// 	req := httptest.NewRequest("GET", "/protected", nil)
// 	w := httptest.NewRecorder()

// 	r.ServeHTTP(w, req)

// 	assert.Equal(t, http.StatusUnauthorized, w.Code)
// 	assert.Contains(t, w.Body.String(), "Authorization header required")
// }

// // 无效 Token 格式测试
// func TestInvalidTokenFormat(t *testing.T) {
// 	r, _ := setupTestRouter()

// 	req := httptest.NewRequest("GET", "/protected", nil)
// 	req.Header.Set("Authorization", "InvalidFormat")
// 	w := httptest.NewRecorder()

// 	r.ServeHTTP(w, req)

// 	assert.Equal(t, http.StatusUnauthorized, w.Code)
// 	assert.Contains(t, w.Body.String(), "Invalid authorization format")
// }

// // 已撤销 Token 测试
// func TestRevokedToken(t *testing.T) {
// 	r, handler := setupTestRouter()

// 	userID := uint(1002)
// 	token, err := handler.ReleaseToken(userID)
// 	assert.NoError(t, err)

// 	// 撤销Token
// 	err = handler.RevokeToken(token)
// 	assert.NoError(t, err)

// 	req := httptest.NewRequest("GET", "/protected", nil)
// 	req.Header.Set("Authorization", "Bearer "+token)
// 	w := httptest.NewRecorder()

// 	r.ServeHTTP(w, req)

// 	assert.Equal(t, http.StatusUnauthorized, w.Code)
// 	assert.Contains(t, w.Body.String(), "Token revoked")
// }

// // 过期 Token 但处于宽限期测试
// func TestExpiredTokenInGracePeriod(t *testing.T) {
// 	// 1. 初始化测试环境（使用极短的过期时间和明确的宽限期）
// 	config := &Config{
// 		SigningKey:  []byte("grace-period-test-key"),
// 		Issuer:      "test-issuer",
// 		Expires:     1, // 1秒后过期
// 		GracePeriod: 5, // 10秒宽限期
// 		Cache: CacheConfig{
// 			Type: "memory",
// 		},
// 	}

// 	handler, err := NewJwtHandler(config)
// 	assert.NoError(t, err)
// 	defer handler.Close()

// 	r := gin.New()
// 	r.Use(handler.GinMiddleware())
// 	r.GET("/grace", func(c *gin.Context) {
// 		userID, _ := c.Get("userID")
// 		c.JSON(http.StatusOK, gin.H{"userID": userID})
// 	})

// 	// 2. 生成并立即让Token过期
// 	userID := uint(999)
// 	token, err := handler.ReleaseToken(userID)
// 	assert.NoError(t, err)

// 	// 等待Token过期（超过Expires时间但仍在GracePeriod内）
// 	time.Sleep(2 * time.Second)

// 	// 3. 测试宽限期内的首次请求
// 	t.Run("FirstRequestInGracePeriod", func(t *testing.T) {
// 		req := httptest.NewRequest("GET", "/grace", nil)
// 		req.Header.Set("Authorization", "Bearer "+token)
// 		w := httptest.NewRecorder()

// 		r.ServeHTTP(w, req)

// 		// 验证：应该返回200且携带新Token
// 		assert.Equal(t, http.StatusOK, w.Code, "应在宽限期内允许访问")
// 		assert.Contains(t, w.Body.String(), `"userID":999`, "应正确传递用户ID")

// 		newToken := w.Header().Get("Authorization")
// 		assert.NotEmpty(t, newToken, "应返回新Token")
// 		assert.NotEqual(t, "Bearer "+token, newToken, "新Token不应与旧Token相同")

// 		// 验证新Token是否有效
// 		req.Header.Set("Authorization", newToken)
// 		w = httptest.NewRecorder()
// 		r.ServeHTTP(w, req)
// 		assert.Equal(t, http.StatusOK, w.Code, "新Token应完全有效")
// 	})

// 	// 4. 测试宽限期内的后续请求
// 	t.Run("SubsequentRequestsInGracePeriod", func(t *testing.T) {
// 		req := httptest.NewRequest("GET", "/grace", nil)
// 		req.Header.Set("Authorization", "Bearer "+token)
// 		w := httptest.NewRecorder()

// 		r.ServeHTTP(w, req)

// 		// 验证：仍应返回200但不再返回新Token（因为首次请求已生成）
// 		assert.Equal(t, http.StatusOK, w.Code)
// 		assert.Empty(t, w.Header().Get("Authorization"), "后续请求不应再返回新Token")
// 	})

// 	// 5. 测试超过宽限期的情况
// 	t.Run("AfterGracePeriod", func(t *testing.T) {
// 		// 等待超过宽限期
// 		time.Sleep(time.Duration(config.GracePeriod+2) * time.Second)

// 		req := httptest.NewRequest("GET", "/grace", nil)
// 		req.Header.Set("Authorization", "Bearer "+token)
// 		w := httptest.NewRecorder()

// 		r.ServeHTTP(w, req)
// 		// 验证：应返回401且Token被撤销
// 		assert.Equal(t, http.StatusUnauthorized, w.Code, "超过宽限期应拒绝访问")
// 		assert.Contains(t, w.Body.String(), "Token revoked", "宽限期后Token应被撤销")

// 		// 验证Token是否被加入黑名单
// 		revoked := handler.isTokenRevoked(token)
// 		assert.True(t, revoked, "超过宽限期的Token应被自动撤销")
// 	})
// }

// 完全过期的 Token（超过宽限期）测试
func TestFullyExpiredToken(t *testing.T) {
	// 1. 初始化测试环境（配置立即过期且无宽限期）
	config := &Config{
		SigningKey:  []byte("expired-test-key"),
		Issuer:      "test-issuer",
		Expires:     -1, // 立即过期
		GracePeriod: 0,  // 无宽限期
		Cache: CacheConfig{
			Type: "memory",
		},
	}

	handler, err := NewJwtHandler(config)
	assert.NoError(t, err)
	defer handler.Close()

	r := gin.New()
	r.Use(handler.GinMiddleware())
	r.GET("/expired", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "success"})
	})

	// 2. 生成测试Token（会自动过期）
	userID := uint(1001)
	token, err := handler.ReleaseToken(userID)
	assert.NoError(t, err)

	// 3. 测试完全过期的Token
	t.Run("FullyExpired", func(t *testing.T) {
		time.Sleep(1 * time.Second)
		// 第一次请求（不检查结果，最后一次会放行）
		req1 := httptest.NewRequest("GET", "/expired", nil)
		req1.Header.Set("Authorization", "Bearer "+token)
		w1 := httptest.NewRecorder()
		r.ServeHTTP(w1, req1) // 发送第一次请求

		// 第二次请求（真正要测试的）
		req2 := httptest.NewRequest("GET", "/expired", nil)
		req2.Header.Set("Authorization", "Bearer "+token)
		w2 := httptest.NewRecorder()
		r.ServeHTTP(w2, req2) // 发送第二次请求

		// 验证应返回401错误
		assert.Equal(t, http.StatusUnauthorized, w2.Code)
		assert.Contains(t, w2.Body.String(), "Token expired")

		// 验证是否自动加入黑名单（根据实现逻辑）
		if config.BlacklistCleanDuration > 0 {
			revoked := handler.isTokenRevoked(token)
			assert.NoError(t, errors.New("Token revoked"), "Token应被加入黑名单")
			assert.True(t, revoked, "完全过期的Token应被自动撤销")
		}
	})

	// 4. 测试过期Token的重复使用
	t.Run("ReuseExpiredToken", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/expired", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		// 再次使用应得到相同错误
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	// 5. 测试带宽限期的对比场景
	t.Run("CompareWithGracePeriod", func(t *testing.T) {
		// 创建有宽限期的配置对比
		graceConfig := &Config{
			SigningKey:  []byte("grace-test-key"),
			Expires:     -1, // 立即过期
			GracePeriod: 5,  // 5秒宽限期
			Cache: CacheConfig{
				Type: "memory",
			},
		}

		graceHandler, _ := NewJwtHandler(graceConfig)
		defer graceHandler.Close()

		graceToken, _ := graceHandler.ReleaseToken(userID)

		req := httptest.NewRequest("GET", "/expired", nil)
		req.Header.Set("Authorization", "Bearer "+graceToken)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		// 有宽限期的应能通过（返回新Token）
		assert.Equal(t, http.StatusOK, w.Code)
		assert.NotEmpty(t, w.Header().Get("Authorization"))
	})
}

// 登录路由测试
func TestLoginRoute(t *testing.T) {
	config := &Config{
		SigningKey: []byte("test-secret-key"),
		Cache: CacheConfig{
			Type: "memory",
		},
	}

	handler, _ := NewJwtHandler(config)

	r := gin.New()
	v1 := r.Group("/v1")
	auth := v1.Group("/auth")
	{
		auth.POST("/login", func(ctx *gin.Context) {
			userIdStr := ctx.PostForm("user_id")
			userInt, _ := strconv.Atoi(userIdStr)
			userId := uint(userInt)
			token, err := handler.ReleaseToken(userId)
			if err != nil {
				ctx.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": "登录失败"})
				return
			}
			ctx.JSON(http.StatusOK, gin.H{"code": 200, "data": token, "msg": "登录成功"})
		})

		auth.POST("/login1", handler.GinMiddleware(), func(ctx *gin.Context) {
			userID, _ := ctx.Get("userID")
			ctx.JSON(http.StatusOK, gin.H{"code": 200, "data": userID, "msg": "登录成功"})
		})
	}

	// 测试/login
	t.Run("TestLogin", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader("user_id=1005"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `"code":200`)
		assert.Contains(t, w.Body.String(), `"msg":"登录成功"`)
	})

	// 测试/login1 带有效Token
	t.Run("TestLogin1WithValidToken", func(t *testing.T) {
		// 先获取Token
		userID := uint(1006)
		token, _ := handler.ReleaseToken(userID)

		req := httptest.NewRequest("POST", "/v1/auth/login1", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `"data":1006`)
	})

	// 测试/login1 带无效Token
	t.Run("TestLogin1WithInvalidToken", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/v1/auth/login1", nil)
		req.Header.Set("Authorization", "Bearer invalidtoken")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
