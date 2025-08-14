/**
 * @Author: guxline zjguoxin@163.com
 * @Date: 2025/7/7 07:09:32
 * @LastEditors: guxline zjguoxin@163.com
 * @LastEditTime: 2025/7/7 07:09:32
 * Description:	结构体
 * Copyright: Copyright (©) 2025 中易综服. All rights reserved.
 */
package gosjwt

import (
	"github.com/dgrijalva/jwt-go"
)

type Claims struct {
	UserId uint
	jwt.StandardClaims
}

type CacheConfig struct {
	Type      string // "memory" 或 "redis"
	RedisAddr string // Redis地址，如 "localhost:6379"
	RedisPass string // Redis密码
	RedisDB   int    // Redis数据库
	Prefix    string // 缓存前缀
}

type Config struct {
	SigningKey             []byte
	Issuer                 string
	Expires                int         // 过期时间(小时)
	Cache                  CacheConfig // 缓存配置
	GracePeriod            int         // 宽限期(秒)
	BlacklistCleanDuration int         // 宽限期/黑名单清理间隔(分钟)
}
