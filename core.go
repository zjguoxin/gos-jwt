/**
 * @Author: guxline zjguoxin@163.com
 * @Date: 2025/7/7 07:08:52
 * @LastEditors: guxline zjguoxin@163.com
 * @LastEditTime: 2025/7/7 07:08:52
 * Description: 核心功能
 * Copyright: Copyright (©) 2025 中易综服. All rights reserved.
 */
package gosjwt

import (
	"fmt"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/zjguoxin/goscache/v2/cache"
)

type gracePeriodToken struct {
	deadline time.Time // 绝对截止时间
	newToken string
}

type JwtHandler struct {
	Config      *Config
	tokenCache  cache.CacheInterface
	blacklist   cache.CacheInterface
	graceTokens map[string]*gracePeriodToken // 记录宽限期内的Token
	graceMutex  sync.Mutex
}

func NewJwtHandler(config *Config) (*JwtHandler, error) {
	// 初始化Token缓存
	tokenCache, err := createCache(config.Cache, "token:")
	if err != nil {
		return nil, fmt.Errorf("初始化Token缓存失败: %v", err)
	}

	// 初始化黑名单缓存
	blacklist, err := createCache(config.Cache, "blacklist:")
	if err != nil {
		return nil, fmt.Errorf("初始化黑名单缓存失败: %v", err)
	}

	// 初始化宽限期清理定时器
	handler := &JwtHandler{
		Config:      config,
		tokenCache:  tokenCache,
		blacklist:   blacklist,
		graceTokens: make(map[string]*gracePeriodToken),
	}

	// 启动后台协程定期清理过期的宽限期Token
	go handler.startGracePeriodCleaner()

	return handler, nil
}

// createCache 创建具体缓存实例
func createCache(cfg CacheConfig, suffix string) (cache.CacheInterface, error) {
	if cfg.Type == "redis" {
		redisCache, err := cache.NewCache(cache.CacheTypeRedis,
			cache.WithRedisConfig(cfg.RedisAddr, cfg.RedisPass, cfg.Prefix+suffix, cfg.RedisDB),
			cache.WithHashExpiry(30*time.Minute),
			cache.WithPoolConfig(100, 20), // 增加连接池大小
			cache.WithHashExpiry(30*time.Minute),
		)
		if err != nil {
			fmt.Println("Redis连接失败，回退到内存缓存:", err)
			// 回退到内存缓存
			memCache, err := cache.NewCache(cache.CacheTypeMemory)
			if err != nil {
				return nil, fmt.Errorf("内存缓存初始化失败: %v", err)
			}
			return memCache, nil
		}
		return redisCache, nil
	}

	// 默认使用内存缓存
	memCache, err := cache.NewCache(cache.CacheTypeMemory)
	if err != nil {
		return nil, fmt.Errorf("内存缓存初始化失败: %v", err)
	}
	return memCache, nil
}

// ReleaseToken 生成并缓存Token
func (j *JwtHandler) ReleaseToken(userId uint) (string, error) {
	expirationTime := time.Now().Add(time.Duration(j.Config.Expires) * time.Second)

	claims := &Claims{
		UserId: userId,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    j.Config.Issuer,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(j.Config.SigningKey)
	if err != nil {
		return "", fmt.Errorf("生成Token失败: %v", err)
	}

	// 存储到缓存
	userData := map[string]interface{}{
		"userId":    userId,
		"expiresAt": claims.ExpiresAt,
	}
	err = j.tokenCache.SetHash(tokenString, userData, time.Until(expirationTime))
	if err != nil {
		return "", fmt.Errorf("缓存Token失败: %v", err)
	}

	return tokenString, nil
}

// ParseToken 解析并验证Token
func (j *JwtHandler) ParseToken(tokenString string) (*jwt.Token, *Claims, error) {
	// 检查黑名单
	if j.blacklist != nil {
		if exists, err := j.blacklist.Exists(tokenString); err == nil && exists {
			return nil, nil, fmt.Errorf("token已被撤销")
		}
	}

	// 尝试从缓存获取
	if cachedData, err := j.tokenCache.GetHash(tokenString); err == nil && len(cachedData) > 0 {
		if userId, ok := cachedData["userId"].(uint); ok {
			if expiresAt, ok := cachedData["expiresAt"].(int64); ok && expiresAt > time.Now().Unix() {
				claims := &Claims{
					UserId: userId,
					StandardClaims: jwt.StandardClaims{
						ExpiresAt: expiresAt,
						Issuer:    j.Config.Issuer,
					},
				}
				return &jwt.Token{Valid: true}, claims, nil
			}
		}
	}

	// 正常解析流程
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (i interface{}, err error) {
		return j.Config.SigningKey, nil
	})

	if err != nil {
		return nil, nil, err
	}

	if !token.Valid {
		return nil, nil, fmt.Errorf("无效的token")
	}

	// // 更新缓存
	// userData := map[string]interface{}{
	// 	"userId":    claims.UserId,
	// 	"expiresAt": claims.ExpiresAt,
	// }

	// // 重新设置过期时间
	// err = j.tokenCache.SetHash(tokenString, userData, time.Until(time.Unix(claims.ExpiresAt, 0)))
	// if err != nil {
	// 	return nil, nil, err
	// }

	return token, claims, nil
}

// RevokeToken 撤销Token
func (j *JwtHandler) RevokeToken(tokenString string) error {
	if tokenString == "" {
		return fmt.Errorf("token不能为空")
	}
	if j.blacklist == nil {
		return fmt.Errorf("黑名单缓存未初始化")
	}
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (i interface{}, err error) {
		return j.Config.SigningKey, nil
	})

	// 即使解析失败（如过期）也加入黑名单
	if err != nil && !isExpiredError(err) {
		return err
	}
	// 加入黑名单
	remaining := time.Hour * 24 // 默认24小时
	if claims.ExpiresAt > 0 {
		remaining = time.Until(time.Unix(claims.ExpiresAt, 0))
		if remaining < time.Minute {
			remaining = time.Minute
		}
	}

	return j.blacklist.Set(tokenString, true, 100*time.Second)
}

// 启动宽限期Token清理器
func (j *JwtHandler) startGracePeriodCleaner() {
	if j.Config.BlacklistCleanDuration <= 0 {
		return
	}
	ticker := time.NewTicker(time.Duration(j.Config.BlacklistCleanDuration) * time.Minute) // 每分钟检查一次
	defer ticker.Stop()

	for range ticker.C {
		j.cleanExpiredGraceTokens()
	}
}

// 清理过期的宽限期Token
func (j *JwtHandler) cleanExpiredGraceTokens() {
	j.graceMutex.Lock()
	defer j.graceMutex.Unlock()

	now := time.Now()
	for tokenStr, gpToken := range j.graceTokens {
		if now.Sub(gpToken.deadline) > time.Duration(j.Config.GracePeriod)*time.Second {
			delete(j.graceTokens, tokenStr)
			_ = j.RevokeToken(tokenStr) // 加入黑名单
		}
	}
}

func (j *JwtHandler) Close() {
	j.tokenCache.Close()
}

// 检查是否是Token过期错误
func isExpiredError(err error) bool {
	if ve, ok := err.(*jwt.ValidationError); ok {
		return ve.Errors&jwt.ValidationErrorExpired != 0
	}
	return false
}
