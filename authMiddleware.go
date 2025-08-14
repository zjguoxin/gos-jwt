/**
 * @Author: guxline zjguoxin@163.com
 * @Date: 2025/7/7 07:03:50
 * @LastEditors: guxline zjguoxin@163.com
 * @LastEditTime: 2025/7/7 07:03:50
 * Description:
 * Copyright: Copyright (©) 2025 中易综服. All rights reserved.
 */
package gosjwt

import (
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// GinMiddleware 创建JWT认证中间件
func (j *JwtHandler) GinMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization format"})
			return
		}

		if j.isTokenRevoked(tokenString) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token revoked"})
			return
		}

		token, claims, err := j.ParseToken(tokenString)
		if err == nil && token.Valid {
			c.Set("userID", claims.UserId)
			c.Next()
			return
		}

		if isExpiredError(err) {
			j.handleExpiredToken(c, tokenString)
			return
		}

		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
	}
}

// 处理过期Token的宽限期逻辑
func (j *JwtHandler) handleExpiredToken(c *gin.Context, tokenString string) {
	// 1. 解析Token忽略过期错误
	claims, err := j.parseExpiredToken(tokenString)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid expired token"})
		return
	}

	now := time.Now()
	j.graceMutex.Lock()
	defer j.graceMutex.Unlock()

	// 2. 检查是否已超过绝对宽限期截止时间
	if gpToken, exists := j.graceTokens[tokenString]; exists {
		if now.After(gpToken.deadline) {
			// 宽限期已结束
			delete(j.graceTokens, tokenString)
			_ = j.RevokeToken(tokenString)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
			return
		}

		// 仍在宽限期内
		c.Set("userID", claims.UserId)
		c.Next()
		return
	}

	// 3. 首次使用过期Token
	newToken, err := j.ReleaseToken(claims.UserId)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate new token"})
		return
	}

	// 设置绝对截止时间（当前时间+宽限期）
	deadline := now.Add(time.Duration(j.Config.GracePeriod) * time.Second)

	// 记录到宽限期管理
	j.graceTokens[tokenString] = &gracePeriodToken{
		deadline: deadline,
		newToken: newToken,
	}

	// 设置响应头返回新Token
	c.Header("Authorization", "Bearer "+newToken)

	// 异步清理（确保最终会被清理）
	go func() {
		time.Sleep(time.Until(deadline) + time.Second) // 稍多等1秒确保

		j.graceMutex.Lock()
		defer j.graceMutex.Unlock()

		if gpToken, exists := j.graceTokens[tokenString]; exists {
			if time.Now().After(gpToken.deadline) {
				delete(j.graceTokens, tokenString)
				_ = j.RevokeToken(tokenString)
			}
		}
	}()

	// 允许本次请求通过
	c.Set("userID", claims.UserId)
	c.Next()
}

// 解析过期Token（忽略过期错误）
func (j *JwtHandler) parseExpiredToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return j.Config.SigningKey, nil
	})
	if err != nil {
		if isExpiredError(err) {
			return claims, nil // 忽略过期错误
		}
		return nil, err
	}
	return claims, nil
}

// 检查Token是否被撤销
func (j *JwtHandler) isTokenRevoked(tokenString string) bool {
	_, exists, err := j.blacklist.Get(tokenString)
	return err == nil && exists
}
