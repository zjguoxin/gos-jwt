# GOS-JWT JWT Handler for Go

[![Go 参考文档](https://pkg.go.dev/badge/github.com/zjguoxin/gos-jwt.svg)](https://pkg.go.dev/github.com/zjguoxin/gos-jwt)
[![许可证: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

用于处理 JWT 的 Go 库。

## 目录

- [功能特性](#功能特性)
- [安装](#安装)
- [快速开始](#快速开始)
- [配置说明](#配置说明)
- [API 参考](#api-参考)
  - [方法列表](#方法列表)
  - [详细说明](#详细说明)
- [配置结构](#配置结构)
  - [Config](#config-配置结构)
  - [CacheConfig](#cacheconfig-配置结构)
- [许可证](#许可证)
- [作者](#作者)

# 功能特性

✔️ 使用 HMAC 签名生成和验证令牌  
✔️ 支持 Redis 或内存缓存的令牌存储  
✔️ 支持令牌撤销和黑名单功能  
✔️ 过期令牌宽限期处理  
✔️ 可配置的过期时间  
✔️ 线程安全操作

# 安装

```bash
go get github.com/zjguoxin/gos-jwt
```

# 快速开始

```go
package main

import (
	"fmt"
	"time"

	"github.com/zjguoxin/gosjwt"
)

func main() {
	// 初始化配置
	config := &gosjwt.Config{
		SigningKey: []byte("你的密钥"),
		Expires:    3600, // 1小时(秒)
		Issuer:     "你的应用",
		Cache: gosjwt.CacheConfig{
			Type:       "redis",
			RedisAddr:  "localhost:6379",
			RedisPass:  "",
			RedisDB:    0,
			Prefix:     "jwt_",
		},
	}

	// 创建JWT处理器
	handler, err := gosjwt.NewJwtHandler(config)
	if err != nil {
		panic(err)
	}
	defer handler.Close()

	// 为用户123生成令牌
	token, err := handler.ReleaseToken(123)
	if err != nil {
		panic(err)
	}
	fmt.Println("生成的令牌:", token)

	// 验证令牌
	_, claims, err := handler.ParseToken(token)
	if err != nil {
		panic(err)
	}
	fmt.Printf("用户 %d 的有效令牌\n", claims.UserId)

	// 撤销令牌
	err = handler.RevokeToken(token)
	if err != nil {
		panic(err)
	}
	fmt.Println("令牌已撤销")
}
```

# 配置说明

```go
type Config struct {
	SigningKey             []byte      // 签名密钥
	Expires               int         // 令牌过期时间(秒)
	Issuer                string      // 令牌发行者
	Cache                 CacheConfig // 缓存配置
	GracePeriod           int         // 宽限期(秒)
	BlacklistCleanDuration int         // 黑名单清理间隔(分钟)
}

type CacheConfig struct {
	Type      string // "redis" 或 "memory"
	RedisAddr string // Redis地址
	RedisPass string // Redis密码
	RedisDB   int    // Redis数据库
	Prefix    string // 缓存键前缀
}
```

# API 参考

## 方法列表

| 方法名        | 签名                                                                               | 描述                    |
| ------------- | ---------------------------------------------------------------------------------- | ----------------------- |
| NewJwtHandler | `func NewJwtHandler(config *Config) (*JwtHandler, error)`                          | 创建新的 JWT 处理器实例 |
| ReleaseToken  | `func (j *JwtHandler) ReleaseToken(userId uint) (string, error)`                   | 生成并缓存新的 JWT 令牌 |
| ParseToken    | `func (j *JwtHandler) ParseToken(tokenString string) (*jwt.Token, *Claims, error)` | 解析并验证 JWT 令牌     |
| RevokeToken   | `func (j *JwtHandler) RevokeToken(tokenString string) error`                       | 撤销令牌（加入黑名单）  |
| Close         | `func (j *JwtHandler) Close()`                                                     | 关闭处理器并释放资源    |

## 详细说明

### NewJwtHandler

```go
func NewJwtHandler(config *Config) (*JwtHandler, error)
```

#### 参数:

- config \*Config: JWT 配置对象

#### 返回值:

- \*JwtHandler: JWT 处理器实例
- error: 错误信息

#### 示例:

```go
config := &gosjwt.Config{
    SigningKey: []byte("your-secret-key"),
    Expires:    3600,
    Issuer:     "your-app",
}
handler, err := gosjwt.NewJwtHandler(config)
```

### ReleaseToken

```go
func (j *JwtHandler) ReleaseToken(userId uint) (string, error)
```

#### 参数:

- userId uint: 用户 ID

#### 返回值:

- \*JwtHandler: JWT 处理器实例
- \*Claims: 包含的用户声明信息
- error: 错误信息

#### 示例:

```go
token, err := handler.ReleaseToken(123)
```

### ParseToken

```go
func (j *JwtHandler) ParseToken(tokenString string) (*jwt.Token, *Claims, error)
```

#### 参数:

- tokenString string: JWT 令牌字符串

#### 返回值:

- \*jwt.Token: 解析后的 JWT 令牌
- \*Claims: 包含的用户声明信息
- error: 错误信息

#### Claims 结构:

```go
type Claims struct {
    UserId uint
    jwt.StandardClaims
}
```

#### 示例:

```go
token, claims, err := handler.ParseToken(tokenString)
```

### RevokeToken

```go
func (j *JwtHandler) RevokeToken(tokenString string) error
```

#### 参数:

- tokenString string: 要撤销的 JWT 令牌

#### 返回值:

- error: 错误信息

### Close

```go
func (j *JwtHandler) Close()
```

#### 说明:

- 关闭处理器并释放所有资源
- 通常在程序退出前调用

# Config 配置结构

```go
type Config struct {
    SigningKey             []byte      // 签名密钥
    Expires               int         // 过期时间(秒)
    Issuer                string      // 发行者
    Cache                 CacheConfig // 缓存配置
    GracePeriod           int         // 宽限期(秒)
    BlacklistCleanDuration int         // 黑名单清理间隔(分钟)
}
```

# CacheConfig 配置结构

```go
type CacheConfig struct {
    Type      string // "redis" 或 "memory"
    RedisAddr string // Redis地址
    RedisPass string // Redis密码
    RedisDB   int    // Redis数据库
    Prefix    string // 缓存键前缀
}
```

## <span id="许可证">📜 许可证</span>

[MIT](https://github.com/zjguoxin/gos-jwt/blob/main/LICENSE)© zjguoxin

### 作者

[zjguoxin@163.com](https://github.com/zjguoxin)
